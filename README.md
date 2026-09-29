# Payments Infrastructure

A production-grade payment system for user-to-user transfers, built in Go 1.26 with PostgreSQL, Redis, and NATS JetStream. Amounts are stored as `int64` minor units (kobo, cents, pence) — the industry standard and the format NIBSS NIP uses on the wire.

---

## Table of Contents

- [What This Is](#what-this-is)
- [What This Is Not](#what-this-is-not)
- [Architecture](#architecture)
- [Data Model](#data-model)
- [The Money Model](#the-money-model)
- [Concurrency: The Double-Withdrawal Problem](#concurrency-the-double-withdrawal-problem)
- [User Lifecycle](#user-lifecycle)
- [Security & Compliance](#security--compliance)
- [Project Layout](#project-layout)
- [Getting Started](#getting-started)
- [API Reference](#api-reference)
- [Operations](#operations)
- [Known Gaps](#known-gaps)

---

## What This Is

A minimal but correct payment core:

- **User registration** with a `pending` → `active` lifecycle gated by email and phone verification
- **Wallets** with race-safe `debit`, `credit`, and `transfer` primitives
- **Double-entry ledger** — every money movement produces balanced entries that sum to zero
- **Idempotent transfers** — same `Idempotency-Key` + same body returns the same response
- **Hash-chained audit log** — every state change is appended and verifiable
- **JWT RS256 auth** with refresh token rotation and account lockout
- **AES-256-GCM encryption** for PII at rest (BVN, NIN, phone)
- **Fraud checks** on every transfer, with AML alert persistence
- **Reconciliation** — nightly comparison of cached balances vs. ledger sums
- **Structured logging**, Prometheus metrics, and graceful shutdown

It is designed to be extended. The ledger, wallet, and payment modules are stable foundations; new payment rails (card, NIP, bank transfer) plug in at the payment orchestration layer without touching the invariants.

---

## What This Is Not

To avoid ambiguity:

- **No NIBSS NIP adapter.** Integration with the Nigerian interbank switch requires CBN licensing, RSA key exchange with NIBSS, NCS certification, and a full ISO 8583 / NIP message implementation. That is a separate project.
- **No merchant model.** This is user-to-user. Merchants, CAC verification, and settlement accounts are not implemented.
- **No webhook delivery worker.** The `webhook_endpoints` and `webhook_deliveries` tables exist, and the outbox publishes events, but no worker reads the delivery queue.
- **No queue consumer.** The outbox worker publishes to NATS, but there is no subscriber reading events and acting on them.
- **No admin panel.** Admin actions (suspend user, freeze wallet, refund) must be performed via SQL or added later.
- **No frontend.** HTTP API only.
- **No production deployment manifests.** Docker Compose is for local development. Kubernetes, Terraform, and secrets management (Vault / AWS KMS) are not included.

---

## Architecture

```
                            ┌─────────────────┐
                            │   Client / SDK  │
                            └────────┬────────┘
                                     │ HTTPS (TLS 1.3)
                                     ▼
                    ┌────────────────────────────────┐
                    │       Load Balancer / WAF      │
                    └────────────────┬───────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              ▼                      ▼                      ▼
      ┌──────────────┐       ┌──────────────┐       ┌──────────────┐
      │   API #1     │       │   API #2     │  ...  │   API #N     │
      │ (stateless)  │       │ (stateless)  │       │ (stateless)  │
      └──────┬───────┘       └──────┬───────┘       └──────┬───────┘
             │                      │                      │
             └──────────┬───────────┴──────────┬───────────┘
                        │                      │
              ┌─────────▼──────────┐  ┌────────▼──────────┐
              │      Redis         │  │    PostgreSQL     │
              │  · cache (balance) │  │  · users          │
              │  · distributed     │  │  · wallets        │
              │    locks           │  │  · ledger_entries │
              │  · rate limiting   │  │  · audit_log      │
              └────────────────────┘  │  · outbox         │
                                      │  (source of truth)│
                                      └────────┬──────────┘
                                               │ outbox poll
                                               │ (FOR UPDATE
                                               │  SKIP LOCKED)
                                               ▼
                                      ┌────────────────────┐
                                      │       Worker       │
                                      │  · outbox publisher│
                                      │  · reconciliation  │
                                      │  · audit verifier  │
                                      └─────────┬──────────┘
                                                │ publish
                                                ▼
                                      ┌────────────────────┐
                                      │   NATS JetStream   │
                                      │  · events (180d)   │
                                      └────────────────────┘
```

### Design Principles

1. **Money movement happens inside one PostgreSQL transaction.** The wallet debit, the ledger entries, the outbox event, and the audit record all commit together or not at all.
2. **Redis is a cache, not a source of truth.** Balance reads may be served from Redis; balance *writes* and *pre-write checks* always hit PostgreSQL.
3. **The queue is for side effects.** Webhooks, notifications, and downstream analytics flow through the outbox → NATS path. Never the money itself.
4. **The ledger is append-only.** A database trigger rejects `UPDATE` and `DELETE` on `ledger_entries`. Corrections are new entries, never edits.
5. **Balances are a cache.** `wallets.balance` is derivable from `SUM(ledger_entries.amount)` at any time. If the two ever disagree, the ledger is correct and the cache is rebuilt.

### Why Monolith, Not Microservices

Microservices would force saga coordination across wallet, ledger, and outbox boundaries. Every saga introduces a window where money has moved but the ledger does not know, or vice versa. The atomic unit of money movement must be a single ACID transaction. Module boundaries are enforced by package structure — extraction to services is possible later, once the boundaries are proven.

---

## Data Model

```
┌─────────────┐          ┌──────────────┐          ┌───────────────┐
│   users     │          │   wallets    │          │ transactions  │
├─────────────┤          ├──────────────┤          ├───────────────┤
│ id          │◄────┐    │ id           │◄────┐    │ id            │
│ email       │     │    │ user_id      │     │    │ type          │
│ status      │     └────│ currency     │     │    │ status        │
│ kyc_tier    │          │ balance  BIGINT   │    │ reference     │
│ ...         │          │ version      │     │    │ end_to_end_id │
└─────────────┘          │ status       │     │    │ metadata      │
                         │ CHECK (bal>=0)│     │    └───────┬───────┘
                         └──────────────┘     │            │
                                              │            │
                         ┌────────────────────┘            │
                         │                                 │
                         ▼                                 ▼
                 ┌──────────────────────────────────────────────┐
                 │           ledger_entries (append-only)       │
                 ├──────────────────────────────────────────────┤
                 │ id         BIGSERIAL                         │
                 │ transaction_id  →  transactions(id)          │
                 │ wallet_id       →  wallets(id)               │
                 │ amount          BIGINT  (signed minor units) │
                 │ currency        CHAR(3)                      │
                 └──────────────────────────────────────────────┘
```

### Tables

| Table | Purpose | Key constraints |
|---|---|---|
| `currencies` | Currency metadata (decimals, symbol) | — |
| `users` | User identity, KYC tier, status | `email UNIQUE`, `status IN (pending,active,suspended,closed)` |
| `verification_tokens` | Email/phone verification, password reset | `token_hash UNIQUE`, single-use |
| `refresh_tokens` | JWT refresh rotation | `token_hash UNIQUE`, revocable |
| `wallets` | Balance cache per user per currency | `UNIQUE (user_id, currency)`, `CHECK (balance >= 0)` |
| `transactions` | Transaction header | — |
| `ledger_entries` | Immutable money movements | Append-only trigger |
| `idempotency_keys` | Request deduplication | `key PRIMARY KEY` |
| `audit_log` | Hash-chained event log | Append-only trigger, chain verifiable |
| `outbox` | Transactional outbox for events | Partial index on unpublished rows |
| `aml_alerts` | AML/fraud alerts for CBN reporting | — |
| `transaction_limits` | CBN tiered limits (in minor units) | — |
| `webhook_endpoints` | User-registered webhook URLs | — |
| `webhook_deliveries` | Pending/retrying webhook deliveries | — |
| `processed_messages` | Idempotent consumer tracking | `(consumer_name, message_id) PRIMARY KEY` |
| `ledger_snapshots` | Periodic balance snapshots | — |
| `reconciliation_runs` | Nightly reconciliation history | — |

---

## The Money Model

**All amounts are `int64` minor units.** No floats. No `NUMERIC`. No `decimal`.

For NGN: `1 naira = 100 kobo`. The value `500050` means ₦5,000.50.
For USD: `1 dollar = 100 cents`. The value `500050` means $5,000.50.
For JPY: `1 yen` (no subunit). The value `5000` means ¥5,000.

### Why Minor Units

Every major payment API uses integer minor units:

| Provider | Format |
|---|---|
| Stripe | Integer minor units |
| Paystack | Integer kobo |
| Flutterwave | Integer minor units |
| Adyen | Integer minor units |
| **NIBSS NIP** | **Integer kobo on the wire** |

Storing decimals forces a conversion on every transfer to and from NIP. Each conversion is a rounding bug waiting to happen. Storing minor units makes the wire format and the storage format identical.

### API Boundary

The HTTP API accepts decimal strings (`"5000.50"`) because that is what humans and SDKs send. The parser converts to minor units immediately:

```go
amount, err := money.ParseMajor("5000.50", money.NGN)
// amount.Minor == 500050
```

Internal code never sees decimals. Arithmetic is integer arithmetic — exact, fast, and impossible to round incorrectly.

### Precision

`ParseMajor` rejects inputs with more decimal places than the currency allows. `"5000.555"` as NGN fails with `ErrPrecision`. This prevents silent truncation of a client's input.

### Formatting

Responses include both the raw minor units and a display string:

```json
{
  "new_balance_minor": 500050,
  "new_balance_display": "NGN 5000.50"
}
```

The minor units are the source of truth. The display string is convenience.

---

## Concurrency: The Double-Withdrawal Problem

Consider two concurrent $100 withdrawals against a $100 wallet:

```
Time    Request A                    Request B
────    ──────────────────────────    ──────────────────────────
T0      BEGIN
T1      SELECT balance → 100
T2                                    BEGIN
T3                                    SELECT balance → 100
T4      if 100 >= 100: OK
T5                                    if 100 >= 100: OK
T6      UPDATE balance = 0
T7      COMMIT (balance = 0)
T8                                    UPDATE balance = -100
T9                                    COMMIT (balance = -100)
```

Both requests succeeded. The wallet is now over-drawn by $100. This is the **write-skew** anomaly. Under PostgreSQL's default `READ COMMITTED` isolation, the `SELECT` returns a snapshot that is stale by the time the `UPDATE` executes.

### The Fix: Three Layers

| Layer | Mechanism | When it fires | Where in code |
|---|---|---|---|
| **Pessimistic lock** | `SELECT ... FOR UPDATE` | At read: Request B blocks until A commits | `wallet.Service.lock` |
| **Optimistic concurrency** | `version` column in `WHERE` clause | At write: stale version → 0 rows affected | `wallet.Service.applyDelta` |
| **DB CHECK constraint** | `CHECK (balance >= 0)` | At write: PostgreSQL rejects negative, SQLSTATE 23514 | `migrations/00006_wallets.sql` |

Each layer is independently sufficient. Together they make negative balances structurally impossible.

- **Layer 1** serializes the read-check-write sequence. Request B physically cannot see the balance until Request A has committed its new value.
- **Layer 2** catches any code path that bypassed the lock. A stale `WHERE version = $N` matches 0 rows and returns `ErrStaleVersion`.
- **Layer 3** catches everything else. Raw SQL, migrations, and bugs. If a write would produce a negative balance, PostgreSQL rejects it.

### Deadlock Prevention

When two transfers touch the same pair of wallets in opposite directions (A→B and B→A concurrently), the wallets must be locked in a deterministic order. `wallet.Service.lockMany` sorts wallet IDs lexicographically before issuing `SELECT ... FOR UPDATE`, so both transactions acquire locks in the same order. No deadlock is possible.

### Proof

`internal/wallet/service_test.go` spawns 200 concurrent $100 debits against a $100 wallet and asserts:

- Exactly 1 succeeds
- 199 fail with `ErrInsufficientFunds`
- Final balance is exactly 0 (never negative)
- Version incremented exactly twice (one credit, one debit)

Run with `go test -race -count=20 ./internal/wallet/...`.

---

## User Lifecycle

```
                    ┌──────────┐
                    │ PENDING  │  ← registration creates this
                    └────┬─────┘
                         │
              email verified AND phone verified
                         │
                         ▼
                    ┌──────────┐
                    │  ACTIVE  │  ← can transact
                    └────┬─────┘
                         │
              admin action / fraud / CBN directive
                         │
                         ▼
                    ┌──────────┐
                    │SUSPENDED │  ← cannot transact
                    └────┬─────┘
                         │
                         ▼
                    ┌──────────┐
                    │  CLOSED  │  ← terminal
                    └──────────┘
```

### Transition Rules

| From | To | Requires |
|---|---|---|
| `pending` | `active` | Both `email_verified_at` and `phone_verified_at` set |
| `pending` | `closed` | Cleanup job after 30 days of inactivity |
| `active` | `suspended` | Admin action + audit entry |
| `suspended` | `active` | Admin action + audit entry |
| any | `closed` | User request or admin action |

The transition to `active` is enforced at the SQL level:

```sql
UPDATE users SET status = 'active'
WHERE id = $1
  AND status = 'pending'
  AND email_verified_at IS NOT NULL
  AND phone_verified_at IS NOT NULL
```

If either verification is missing, the `WHERE` clause matches 0 rows. The database guarantees the invariant regardless of application logic.

### Why This Matters

A user who registers but never verifies their email should not be able to move money. CBN's tiered KYC framework requires identity verification before any financial activity. Starting users in `pending` and gating activation on both verifications is the minimum compliance posture.

---

## Security & Compliance

### Encryption

| Data | Method | Storage |
|---|---|---|
| BVN | AES-256-GCM (AEAD) | `users.bvn_encrypted BYTEA` |
| NIN | AES-256-GCM (AEAD) | `users.nin_encrypted BYTEA` |
| Webhook HMAC secrets | AES-256-GCM (AEAD) | `webhook_endpoints.secret_encrypted BYTEA` |
| Passwords | bcrypt cost 12 (~250ms) | `users.password_hash` |
| Refresh tokens | SHA-256 hash | `refresh_tokens.token_hash` |
| Verification tokens | SHA-256 hash | `verification_tokens.token_hash` |

The encryption key is loaded from `ENCRYPTION_KEY_B64` (base64, 32 bytes). It must come from a secrets manager (AWS KMS, Vault, Kubernetes Secret). Never commit it.

Per PCI DSS 4.0.1 Requirement 3.5.1.2, disk-level encryption alone does not satisfy the requirement — application-layer encryption is mandatory for sensitive financial identifiers. AES-256-GCM is an AEAD cipher: it authenticates before decrypting, so any ciphertext tampering causes `Decrypt` to fail rather than returning corrupted plaintext.

### Authentication

- **JWT RS256** — asymmetric signing. The API holds the private key; downstream services verify with the public key. No service can mint tokens it cannot sign.
- **Algorithm pinning** — `jwt.Parse` rejects any signing method that is not RSA. This blocks the `alg: none` and algorithm-confusion attack classes.
- **Refresh rotation** — a refresh token is revoked and replaced on every use. A replayed token fails.
- **Account lockout** — 5 failed logins in 15 minutes locks the account.
- **Constant-time login** — a precomputed bcrypt hash ensures that nonexistent emails take the same time to reject as existing ones, preventing user enumeration.

### Transport

- TLS 1.3 minimum
- mTLS for service-to-service (configurable via `MTLS_ENABLED`)
- Trusted proxy detection for correct client IP extraction

### Authorization

- Every wallet endpoint calls `ownerCheck`, which verifies that the authenticated user owns the wallet. This addresses OWASP API1:2025 (Broken Object Level Authorization), the most common API vulnerability in fintech.

### Rate Limiting

Per-principal token bucket in `httpx.RateLimiter`. Unauthenticated requests are keyed by client IP; authenticated requests by JWT subject. Configurable rate and burst.

### Audit

Every state change writes a row to `audit_log`. The log is hash-chained: each row includes the SHA-256 of the previous row's canonical form. Tampering with any historical row breaks the chain and is detectable by `audit.VerifyChain`, which the worker runs nightly.

The `audit_log` table has a trigger that rejects `UPDATE` and `DELETE`. Combined with the hash chain, this makes the log append-only and tamper-evident at both the database level and the cryptographic level.

### Logging

Structured `slog` output. Sensitive headers (`Authorization`, `Cookie`, `X-Api-Key`) are never logged. Panics are recovered, logged with the request ID, and returned as generic 500s — stack traces never leak to clients.

### Compliance Mapping

| Requirement | Implementation |
|---|---|
| PCI DSS 3.5.1.2 — application-layer encryption | AES-256-GCM in `internal/crypto` |
| PCI DSS 4.2 — TLS 1.3 in transit | `auth.MTLSConfig`, TLS min version 1.3 |
| PCI DSS 8.4 — MFA for CDE access | `auth.Claims.HasMFA`, `httpx.RequireMFA` |
| PCI DSS 10.2 — audit trails | Hash-chained `audit_log` |
| ISO 27001 A.8.27 — no secrets in logs | `slog` with header redaction |
| OWASP API1:2025 — BOLA | `Handler.ownerCheck` |
| OWASP API2:2025 — Broken auth | JWT RS256 with algorithm pinning |
| OWASP API4:2025 — rate limiting | `httpx.RateLimiter` |
| NDPA 2023 — explicit consent | `users.consent_given_at`, `user_consents` table |
| NDPA 2023 — encryption of BVN/NIN | `users.bvn_encrypted`, `users.nin_encrypted` |
| AML/CFT/CPF — real-time monitoring | `fraud.Service.Check` writes to `aml_alerts` |
| CBN tiered limits | `transaction_limits` table |
| CBN immutability | Append-only triggers on `ledger_entries` and `audit_log` |

---

## Project Layout

```
payments-infra/
├── cmd/
│   ├── api/                    # HTTP API server
│   ├── worker/                 # Outbox, reconciliation, audit verifier
│   └── migrate/                # Goose migration runner (embedded)
├── internal/
│   ├── money/                  # int64 minor units + currency
│   ├── crypto/                 # AES-256-GCM for PII at rest
│   ├── user/                   # Registration, verification, auth
│   ├── wallet/                 # FOR UPDATE + OCC + CHECK
│   ├── ledger/                 # Double-entry, append-only
│   ├── payment/                # Transfer orchestration
│   ├── fraud/                  # Synchronous checks + AML alerts
│   ├── audit/                  # Hash-chained audit log
│   ├── auth/                   # JWT RS256 + mTLS
│   ├── httpx/                  # Middleware (log, recovery, metrics, rate limit)
│   ├── httpapi/                # Handlers + router
│   ├── outbox/                 # Transactional outbox
│   ├── queue/                  # NATS JetStream publisher
│   ├── cache/                  # Redis client + distributed locks
│   ├── reconciliation/         # Nightly balance vs ledger comparison
│   └── platform/
│       └── db/                 # pgxpool + WithTx helper
├── migrations/                 # Numbered SQL migrations (goose)
├── deploy/
│   ├── docker-compose.yml      # Postgres + Redis + NATS + API + Worker
│   ├── nats.conf               # JetStream configuration
│   └── secrets/                # gitignored — JWT keys, encryption key
├── Dockerfile                  # Multi-stage, distroless runtime
├── Makefile                    # All developer commands
├── go.mod
└── go.sum
```

---

## Getting Started

### Prerequisites

- Go 1.26+
- Docker and Docker Compose
- `openssl` for key generation
- `uuidgen` for idempotency keys (optional)

### 1. Clone and install dependencies

```bash
git clone https://github.com/yourorg/payments-infra
cd payments-infra

go mod download
go install github.com/pressly/goose/v3/cmd/goose@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

### 2. Generate secrets

```bash
mkdir -p deploy/secrets

# JWT RS256 key pair
openssl genrsa -out deploy/secrets/jwt_private.pem 4096
openssl rsa -in deploy/secrets/jwt_private.pem \
            -pubout -out deploy/secrets/jwt_public.pem

# AES-256 encryption key for PII at rest
openssl rand -base64 32 > deploy/secrets/encryption.key

# Runtime environment variables
cat > .env <<EOF
POSTGRES_PASSWORD=$(openssl rand -hex 16)
REDIS_PASSWORD=$(openssl rand -hex 16)
ENCRYPTION_KEY_B64=$(cat deploy/secrets/encryption.key)
EOF

# Keep secrets out of git
cat > .gitignore <<'EOF'
.env
deploy/secrets/
bin/
coverage.out
EOF
```

### 3. Start the stack

```bash
make docker-up
make docker-logs
```

This starts PostgreSQL, Redis, NATS JetStream, runs migrations, then starts the API and worker.

The API is available at `http://localhost:8443`.

### 4. Register a user

```bash
curl -X POST http://localhost:8443/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "phone": "+2348012345678",
    "password": "correct-horse-battery-staple",
    "full_name": "Alice Okafor",
    "consent_given": true
  }'
```

The response includes `_dev_email_token` and `_dev_phone_token`. In production, these are sent via email and SMS; the `_dev_` prefix signals that they must be removed before deployment.

### 5. Verify email, then phone

```bash
curl -X POST http://localhost:8443/v1/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"token": "<email_token>", "purpose": "email_verify"}'

curl -X POST http://localhost:8443/v1/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"token": "<phone_token>", "purpose": "phone_verify"}'
```

After the second call, `user.status` becomes `active`.

### 6. Log in

```bash
curl -X POST http://localhost:8443/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "correct-horse-battery-staple"}'
```

Save the `access_token`.

### 7. Create a wallet

```bash
curl -X POST http://localhost:8443/v1/wallets \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"currency": "NGN"}'
```

### 8. Transfer ₦5,000.50

```bash
curl -X POST http://localhost:8443/v1/transfers \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{
    "from_wallet_id": "<wallet-uuid>",
    "to_wallet_id": "<recipient-wallet-uuid>",
    "amount": "5000.50",
    "currency": "NGN",
    "reference": "INV-2026-001"
  }'
```

The API parses `"5000.50"` into `500050` kobo and stores that. The response includes both forms:

```json
{
  "transaction_id": "...",
  "status": "posted",
  "new_balance_minor": 500050,
  "new_balance_display": "NGN 5000.50",
  "currency": "NGN"
}
```

---

## API Reference

### Authentication

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/auth/register` | Create user (returns `pending`) |
| `POST` | `/v1/auth/verify` | Verify email or phone |
| `POST` | `/v1/auth/login` | Authenticate, return tokens |
| `POST` | `/v1/auth/refresh` | Rotate refresh token, get new access token |
| `POST` | `/v1/auth/logout` | Revoke refresh token |

### Users

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/users/me` | Current user profile |

### Wallets

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/wallets` | Create wallet for a currency |
| `GET` | `/v1/wallets` | List current user's wallets |
| `GET` | `/v1/wallets/{id}` | Get wallet details |
| `GET` | `/v1/wallets/{id}/transactions` | Paginated transaction history |

### Transfers

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/transfers` | Move funds between wallets |

**Headers for mutating endpoints:**

- `Authorization: Bearer <token>` — required
- `Idempotency-Key: <uuid>` — required for `POST /v1/transfers`

### Error Responses

```json
{"error": "insufficient funds"}
```

| Status | Meaning |
|---|---|
| 400 | Malformed request |
| 401 | Missing or invalid token |
| 403 | Authenticated but not authorized for this resource |
| 404 | Resource not found |
| 409 | Conflict (e.g., duplicate email) |
| 422 | Business rule violation (insufficient funds, currency mismatch) |
| 429 | Rate limit exceeded |
| 500 | Internal server error |

---

## Operations

### Migrations

```bash
# Apply all pending
make migrate-up

# Check status
make migrate-status

# Create a new migration (sequential numbering)
make migrate-create NAME=add_something

# Roll back the last migration
make migrate-down
```

Migrations are embedded in the `migrate` binary at build time and run automatically before the API and worker start in Docker Compose.

### Reconciliation

The worker runs nightly:

1. **Audit chain verification** — recomputes every hash and alerts if the chain is broken
2. **Balance reconciliation** — compares `wallets.balance` against `SUM(ledger_entries.amount)` per wallet; logs any drift

Drift is a correctness incident. The `CHECK` constraint should make it impossible; if it appears, something is deeply wrong and the ledger sum is authoritative.

To reconcile on demand:

```sql
SELECT w.id,
       w.balance AS cached,
       COALESCE(SUM(e.amount), 0) AS ledger_sum,
       (w.balance - COALESCE(SUM(e.amount), 0)) AS drift
FROM wallets w
LEFT JOIN ledger_entries e ON e.wallet_id = w.id
GROUP BY w.id, w.balance
HAVING w.balance <> COALESCE(SUM(e.amount), 0);
```

To repair a drifted wallet:

```sql
UPDATE wallets w
SET balance = sub.sum_amount,
    version = w.version + 1,
    updated_at = now()
FROM (
    SELECT wallet_id, SUM(amount) AS sum_amount
    FROM ledger_entries
    GROUP BY wallet_id
) sub
WHERE w.id = sub.wallet_id;
```

### Metrics

Prometheus metrics are exposed at `GET /metrics`:

- `payments_http_requests_total{method, path, status}`
- `payments_http_duration_seconds{method, path}`

### Health

- `GET /v1/healthz` — liveness (returns 200 if the process is running)

For a deeper readiness check that pings Postgres, Redis, and NATS, add a `/readyz` handler — it is not currently implemented.

### Logs

Structured JSON to stdout:

```json
{
  "time": "2026-09-29T10:30:15.234Z",
  "level": "INFO",
  "msg": "http_request",
  "method": "POST",
  "path": "/v1/transfers",
  "status": 201,
  "duration_ms": 45,
  "request_id": "...",
  "ip": "203.0.113.42",
  "user_id": "..."
}
```

Sensitive headers are never logged.

---

## Known Gaps

These are real, known, and documented so they are not forgotten:

### Correctness

1. **Fraud alerts are lost on transaction rollback.** `fraud.Service.Check` writes to `aml_alerts` inside the payment transaction. If the payment rolls back, the alert disappears. Fix: write AML alerts on a separate connection, outside the transaction.

2. **CBN tiered limits are not enforced.** The `transaction_limits` table exists and is populated, but no code reads it. Add a check inside `payment.Service.Transfer` that sums the user's daily debits and rejects transfers exceeding the tier limit.

3. **No audit record on verification.** `user.Service.VerifyToken` updates `users.status` to `active` but writes no audit row. Add an audit call in the same transaction.

4. **No audit on failed login.** Failed attempts increment `failed_login_count` but are not audited. For CBN compliance, log them.

### Scale

5. **The audit chain uses a global advisory lock.** `audit.Recorder.Record` acquires `pg_advisory_xact_lock(0x6175646974)` on every call, serializing all money movements. At 1,000+ TPS this becomes the bottleneck. Mitigations: batch audit writes, shard the chain by user, or move to a per-partition chain.

6. **Redis is configured but not used by the read path.** The `cache.WalletCache` type exists but no handler calls it. Balance reads hit PostgreSQL every time. Add cache-aside logic to `GetWallet` and invalidate on commit.

7. **No read replicas.** All queries go to the primary. Balance queries and transaction history could be served from replicas.

### Reliability

8. **No queue consumer.** The outbox publishes to NATS, but no worker subscribes. Webhook deliveries, notifications, and downstream AML reporting have no consumer.

9. **No webhook delivery worker.** The `webhook_deliveries` table is populated by nothing, and no worker drains it.

10. **No snapshot job.** `ledger_snapshots` exists but is never written. Add an hourly job to snapshot balances so `RecomputeBalance` stays O(entries since snapshot) instead of O(all entries).

### Compliance

11. **No DPO contact in the codebase.** NDPA 2023 requires a Data Protection Officer. Add a config value and a `/v1/privacy/dpo` endpoint.

12. **No data subject access request flow.** NDPA requires users to export or delete their data on request. Add endpoints, and be careful: transaction records must be retained for AML (5 years), so deletion means PII removal, not row removal.

13. **No sanctions screening.** CBN requires screening against OFAC, UN, and EU lists. The `sanctions_checks` table was removed in a rewrite; add it back and wire it into registration.

### Operations

14. **No readiness endpoint.** `/v1/healthz` returns 200 even if the database is down. Add `/readyz` that pings dependencies.

15. **No CORS configuration.** Browser clients will be blocked.

16. **No OpenAPI spec.** API consumers have no contract. Generate one from handler annotations.

17. **No structured error codes.** Clients get free-text messages. Add machine-readable codes (`AUTH_INVALID_CREDENTIALS`, `USER_NOT_ACTIVE`) so clients can branch on them.

18. **No integration tests against real Postgres.** The `wallet` package has a concurrency test that skips if no test database is available. Add a `testcontainers-go` setup so it always runs.

---

## Summary

This is a solid foundation. The money model is correct (`int64` minor units). The ledger is append-only and hash-chained. The wallet debit path is protected by three independent layers (lock, version, CHECK). Authentication uses RS256 with rotation and lockout. PII is encrypted with AES-256-GCM. The audit log is tamper-evident.

The gaps are documented and mostly additive — none of them invalidate the existing design. The most important to close, in order:

1. Fix the fraud alert rollback bug (correctness)
2. Enforce CBN tier limits (compliance)
3. Add the queue consumer and webhook delivery worker (the events already flow; something must act on them)
4. Add the readiness endpoint and CORS (operational basics)
5. Add OpenAPI and structured error codes (developer experience)

Everything else — read replicas, snapshots, sanctions screening, DPO workflow — can wait until the system is actually deployed and the need is real.