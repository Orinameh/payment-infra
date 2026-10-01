package payment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"payment-infra/internal/fraud"
	"payment-infra/internal/httpx"
	"payment-infra/internal/ledger"
	"payment-infra/internal/money"
	"payment-infra/internal/nibss"
	"payment-infra/internal/nuban"
	"payment-infra/internal/platform/db"
	"payment-infra/internal/wallet"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrProviderUnavailable = errors.New("payment: bank transfer provider unavailable")
	ErrLocalDestination    = errors.New("payment: destination is a local account, use wallet transfer")
	ErrInvalidAccount      = errors.New("payment: invalid destination account")
	ErrInProgress          = errors.New("payment: transfer already in progress, retry shortly")
)

// SettlementUserID owns the per-currency NIP settlement wallets (seeded
// in migration 00023). Outbound bank transfers move user → settlement
// so the ledger stays balanced; the float is swept off-ledger.
var SettlementUserID = uuid.MustParse("deadbeef-0000-4000-8000-000000000001")

// SetBankCode sets our institution code for local-vs-remote routing.
// Empty disables the rail's local checks (name enquiry falls through
// to the provider for every account).
func (s *Service) SetBankCode(code string) { s.bankCode = code }

type EnquiryResult struct {
	AccountName   string `json:"account_name"`
	AccountNumber string `json:"account_number"`
	BankCode      string `json:"bank_code"`
	Currency      string `json:"currency,omitempty"`
	Local         bool   `json:"local"`
}

// NameEnquiry resolves an account to a holder name. NIP requires this
// before a transfer so funds are never misdirected on a typo.
//
// Validation is two layers: the NUBAN check digit proves the number is
// well-formed for the given bank code; existence is proven by lookup
// (local wallets) or the provider (remote banks).
func (s *Service) NameEnquiry(ctx context.Context, accountNumber, bankCode string) (*EnquiryResult, error) {
	if err := nuban.Validate(accountNumber, bankCode); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAccount, err)
	}
	if s.bankCode != "" && bankCode == s.bankCode {
		w, err := s.wallets.GetByAccountNumber(ctx, s.pool, accountNumber)
		if err != nil {
			return nil, err // wallet.ErrNotFound → 404
		}
		if w.Status != "active" {
			return nil, wallet.ErrFrozen
		}
		var name string
		if err := s.pool.QueryRow(ctx,
			`SELECT full_name FROM users WHERE id = $1`, w.UserID,
		).Scan(&name); err != nil {
			return nil, fmt.Errorf("payment: holder lookup: %w", err)
		}
		return &EnquiryResult{
			AccountName: name, AccountNumber: accountNumber,
			BankCode: bankCode, Currency: w.Currency, Local: true,
		}, nil
	}
	if s.nibss == nil {
		return nil, ErrProviderUnavailable
	}
	res, err := s.nibss.NameEnquiry(ctx, nibss.NameEnquiryRequest{
		AccountNumber: accountNumber, BankCode: bankCode,
	})
	if err != nil {
		return nil, err
	}
	return &EnquiryResult{
		AccountName: res.AccountName, AccountNumber: res.AccountNumber,
		BankCode: res.BankCode,
	}, nil
}

type BankTransferRequest struct {
	FromWalletID  uuid.UUID
	AccountNumber string // 10-digit destination NUBAN
	BankCode      string // 3-digit destination bank code
	Amount        money.Money
	Reference     string
	EndToEndID    string
	Narration     string
	IdemKey       string
	Metadata      map[string]any
}

type BankTransferResult struct {
	TransactionID uuid.UUID `json:"transaction_id"`
	Status        string    `json:"status"`
	SessionID     string    `json:"session_id,omitempty"`
	NewBalance    int64     `json:"new_balance_minor"`
	Currency      string    `json:"currency"`
}

// BankTransfer moves funds from a wallet to an external bank account.
//
// Three phases: (1) reserve idempotency, run fraud/tier checks, debit
// user → settlement and post a *pending* transaction; (2) call the NIP
// provider OUTSIDE any DB transaction (network I/O must never hold row
// locks); (3) finalize posted (session id + outbox event) or reverse
// (credit back + reversal entries + failed marking).
//
// The provider reference is our Reference, so a replay after a crash
// between (2) and (3) re-drives settlement idempotently instead of
// double-paying. A replay arriving while the first attempt is still in
// (1) sees status 0 and gets ErrInProgress.
func (s *Service) BankTransfer(ctx context.Context, actorID uuid.UUID,
	req BankTransferRequest) (*BankTransferResult, error) {

	if err := req.Amount.RequirePositive(); err != nil {
		return nil, err
	}
	if req.IdemKey == "" {
		return nil, errors.New("payment: idempotency key required")
	}
	if s.nibss == nil {
		return nil, ErrProviderUnavailable
	}
	if err := nuban.Validate(req.AccountNumber, req.BankCode); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAccount, err)
	}
	if s.bankCode != "" && req.BankCode == s.bankCode {
		w, err := s.wallets.GetByAccountNumber(ctx, s.pool, req.AccountNumber)
		if err == nil && w != nil {
			return nil, ErrLocalDestination
		}
		if err != nil && !errors.Is(err, wallet.ErrNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("payment: unknown local account: %w", wallet.ErrNotFound)
	}

	key := "banktransfer:" + req.IdemKey
	fingerprint, _ := json.Marshal(struct {
		From uuid.UUID      `json:"from"`
		To   string         `json:"to_account"`
		Bank string         `json:"to_bank"`
		Amt  int64          `json:"amount_minor"`
		Ccy  money.Currency `json:"currency"`
		Ref  string         `json:"reference"`
		E2E  string         `json:"end_to_end_id"`
		Meta map[string]any `json:"metadata"`
	}{
		From: req.FromWalletID, To: req.AccountNumber, Bank: req.BankCode,
		Amt: req.Amount.Minor, Ccy: req.Amount.Currency,
		Ref: req.Reference, E2E: req.EndToEndID, Meta: req.Metadata,
	})
	reqHash := hashBody(fingerprint)

	fraudReq := fraud.CheckRequest{
		UserID:   actorID,
		WalletID: req.FromWalletID,
		Amount:   req.Amount,
	}
	var (
		out         *BankTransferResult
		fraudResult *fraud.Result
		fromAcct    string
	)

	// Phase 1: reserve, check, debit to settlement, pending ledger.
	err := db.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		rec, err := reserveIdem(ctx, tx, key, reqHash)
		if err != nil {
			return err
		}
		if rec != nil {
			return json.Unmarshal(rec.body, &out)
		}

		fraudResult, err = s.fraud.Check(ctx, tx, fraudReq)
		if err != nil {
			return err
		}
		if fraudResult.Decision == "block" {
			return fraud.ErrBlocked
		}

		settlement, err := s.wallets.Create(ctx, tx,
			SettlementUserID, string(req.Amount.Currency))
		if err != nil {
			return err
		}

		precheck := func(ctx context.Context, tx pgx.Tx,
			sourceWalletID uuid.UUID, amount money.Money) error {
			return s.checkTierLimit(ctx, tx, actorID, amount)
		}
		if err := s.wallets.Transfer(ctx, tx,
			req.FromWalletID, settlement.ID, req.Amount,
			req.Reference, actorID,
			wallet.WithPrecheck(precheck)); err != nil {
			return err
		}

		fromAcct, err = s.wallets.EnsureAccountNumber(ctx, tx, req.FromWalletID)
		if err != nil {
			return err
		}

		txID, err := s.ledger.Post(ctx, tx, ledger.PostRequest{
			Type:       "bank_transfer_out",
			Status:     "pending",
			Reference:  req.Reference,
			EndToEndID: req.EndToEndID,
			Metadata:   req.Metadata,
			Entries: []ledger.Entry{
				{WalletID: req.FromWalletID, Amount: -req.Amount.Minor, Currency: string(req.Amount.Currency)},
				{WalletID: settlement.ID, Amount: req.Amount.Minor, Currency: string(req.Amount.Currency)},
			},
		})
		if err != nil {
			return err
		}

		from, err := s.wallets.Get(ctx, tx, req.FromWalletID)
		if err != nil {
			return err
		}
		out = &BankTransferResult{
			TransactionID: txID,
			Status:        "pending",
			NewBalance:    from.Balance,
			Currency:      from.Currency,
		}
		return storeIdem(ctx, tx, key, 202, out)
	})

	var txID *uuid.UUID
	if out != nil {
		id := out.TransactionID
		txID = &id
	}
	if fraudResult != nil {
		s.fraud.RecordAlert(ctx, fraudReq, fraudResult, txID)
	}
	if err != nil {
		return nil, fmt.Errorf("payment: bank transfer reserve: %w", err)
	}
	if out.Status == "posted" {
		return out, nil // replay of a completed transfer
	}
	// Pending (fresh or crash-replay): drive settlement. The provider
	// reference is ours, so this is idempotent downstream.

	// Phase 2: provider call, no locks held.
	pres, perr := s.nibss.Transfer(ctx, nibss.TransferRequest{
		FromAccount: fromAcct,
		ToAccount:   req.AccountNumber,
		ToBankCode:  req.BankCode,
		Amount:      req.Amount,
		Narration:   req.Narration,
		Reference:   req.Reference,
	})

	// Phase 3: finalize or reverse.
	if perr == nil {
		finErr := db.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `
				UPDATE transactions
				SET status = 'posted',
				    metadata = metadata || jsonb_build_object('session_id', $1, 'provider', $2)
				WHERE id = $3`, pres.SessionID, s.nibss.Mode(), out.TransactionID)
			if err != nil {
				return err
			}
			if err := s.outbox.Emit(ctx, tx, "transaction", out.TransactionID,
				"payments.bank_transfer_posted", map[string]any{
					"transaction_id": out.TransactionID.String(),
					"from_wallet_id": req.FromWalletID.String(),
					"to_account":     req.AccountNumber,
					"to_bank":        req.BankCode,
					"amount_minor":   req.Amount.Minor,
					"currency":       string(req.Amount.Currency),
					"reference":      req.Reference,
					"session_id":     pres.SessionID,
					"request_id":     httpx.RequestIDFrom(ctx),
				}); err != nil {
				return err
			}
			from, err := s.wallets.Get(ctx, tx, req.FromWalletID)
			if err != nil {
				return err
			}
			out.Status = "posted"
			out.SessionID = pres.SessionID
			out.NewBalance = from.Balance
			return storeIdem(ctx, tx, key, 201, out)
		})
		if finErr != nil {
			return nil, fmt.Errorf("payment: bank transfer finalize: %w", finErr)
		}
		return out, nil
	}

	// Provider failed: reverse the debit so the user is whole, mark the
	// attempt failed, and release the idempotency key for a client retry.
	revErr := db.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		settlement, err := s.wallets.Create(ctx, tx,
			SettlementUserID, string(req.Amount.Currency))
		if err != nil {
			return err
		}
		if err := s.wallets.Transfer(ctx, tx,
			settlement.ID, req.FromWalletID, req.Amount,
			"reversal:"+req.Reference, actorID); err != nil {
			return err
		}
		if _, err := s.ledger.Post(ctx, tx, ledger.PostRequest{
			Type:       "bank_transfer_reversal",
			Reference:  "reversal:" + req.Reference,
			EndToEndID: req.EndToEndID,
			Metadata: map[string]any{
				"reverses": out.TransactionID.String(),
				"reason":   perr.Error(),
			},
			Entries: []ledger.Entry{
				{WalletID: settlement.ID, Amount: -req.Amount.Minor, Currency: string(req.Amount.Currency)},
				{WalletID: req.FromWalletID, Amount: req.Amount.Minor, Currency: string(req.Amount.Currency)},
			},
		}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE transactions
			SET status = 'failed',
			    metadata = metadata || jsonb_build_object('error', $1)
			WHERE id = $2`, perr.Error(), out.TransactionID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM idempotency_keys WHERE key = $1`, key)
		return err
	})
	if revErr != nil {
		return nil, fmt.Errorf("payment: bank transfer failed (%v) and reversal failed (%v)",
			perr, revErr)
	}
	return nil, fmt.Errorf("payment: bank transfer failed: %w", perr)
}
