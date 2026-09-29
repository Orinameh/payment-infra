package httpapi

// Machine-readable error codes. Every error response has the shape:
//
//	{"error": "<human message>", "code": "<STABLE_CODE>"}
//
// Clients must branch on "code", never on "error" (messages may change).
const (
	CodeRequestInvalidJSON       = "REQUEST_INVALID_JSON"
	CodeAuthWeakPassword         = "AUTH_WEAK_PASSWORD"
	CodeAuthConsentRequired      = "AUTH_CONSENT_REQUIRED"
	CodeUserEmailTaken           = "USER_EMAIL_TAKEN"
	CodeUserSanctioned           = "USER_SANCTIONED"
	CodeVerifyInvalidPurpose     = "VERIFY_INVALID_PURPOSE"
	CodeVerifyTokenInvalid       = "VERIFY_TOKEN_INVALID"
	CodeAuthAccountLocked        = "AUTH_ACCOUNT_LOCKED"
	CodeAuthNotActive            = "AUTH_NOT_ACTIVE"
	CodeAuthInvalidCredentials   = "AUTH_INVALID_CREDENTIALS"
	CodeAuthRefreshInvalid       = "AUTH_REFRESH_INVALID"
	CodeUserNotFound             = "USER_NOT_FOUND"
	CodeWalletInvalidID          = "WALLET_INVALID_ID"
	CodeWalletCurrencyInvalid    = "WALLET_CURRENCY_INVALID"
	CodeWalletNotFound           = "WALLET_NOT_FOUND"
	CodeForbidden                = "FORBIDDEN"
	CodePaymentIdempotencyKey    = "PAYMENT_IDEMPOTENCY_KEY_REQUIRED"
	CodeTransferInsufficient     = "TRANSFER_INSUFFICIENT_FUNDS"
	CodeTransferWalletFrozen     = "TRANSFER_WALLET_FROZEN"
	CodeTransferCurrencyMismatch = "TRANSFER_CURRENCY_MISMATCH"
	CodeTransferConflict         = "TRANSFER_CONCURRENT_MODIFICATION"
	CodeTransferLimitExceeded    = "TRANSFER_LIMIT_EXCEEDED"
	CodeTransferBlocked          = "TRANSFER_BLOCKED_FRAUD"
	CodeTransferReview           = "TRANSFER_UNDER_REVIEW"
	CodeServiceUnavailable       = "SERVICE_UNAVAILABLE"
	CodeInternalError            = "INTERNAL_ERROR"
)
