package nibss

import (
	"context"
	"testing"

	"payment-infra/internal/money"
)

func TestDummyRefusesProduction(t *testing.T) {
	if _, err := NewDummyClient(DummyConfig{Environment: "production"}); err == nil {
		t.Fatal("dummy in production must be refused")
	}
}

func TestDummyValidatesTransfer(t *testing.T) {
	c, err := NewDummyClient(DummyConfig{Environment: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := c.Transfer(ctx, TransferRequest{}); err == nil {
		t.Fatal("empty accounts must be rejected")
	}
	neg := TransferRequest{FromAccount: "a", ToAccount: "b", ToBankCode: "001",
		Amount: money.New(-1, money.NGN)}
	if _, err := c.Transfer(ctx, neg); err == nil {
		t.Fatal("non-positive amount must be rejected")
	}
	ok := TransferRequest{FromAccount: "a", ToAccount: "b", ToBankCode: "001",
		Amount: money.New(500050, money.NGN), Reference: "ref-1"}
	res, err := c.Transfer(ctx, ok)
	if err != nil {
		t.Fatal(err)
	}
	if res.ResponseCode != "00" || res.Reference != "ref-1" {
		t.Fatalf("unexpected response: %+v", res)
	}
}

func TestDummyNameEnquiry(t *testing.T) {
	c, _ := NewDummyClient(DummyConfig{Environment: "dev"})
	if _, err := c.NameEnquiry(context.Background(), NameEnquiryRequest{}); err == nil {
		t.Fatal("empty enquiry must be rejected")
	}
	res, err := c.NameEnquiry(context.Background(),
		NameEnquiryRequest{AccountNumber: "0123456789", BankCode: "001"})
	if err != nil || res.AccountName == "" {
		t.Fatalf("got %+v, %v", res, err)
	}
}
