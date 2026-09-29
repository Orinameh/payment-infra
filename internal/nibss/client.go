package nibss

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// Client is the real NIBSS NIP adapter. Every method returns
// ErrNotImplemented until the following are in place:
//
//   - A signed agreement with NIBSS granting an Institution Code
//   - An RSA key pair exchanged with NIBSS and whitelisted
//   - A 24-byte 3DES session key issued by NIBSS
//   - The NIP XML schemas for the endpoints you call
//   - A sandbox URL and NCS test certification
//   - A production certificate and go-live approval
type Client struct {
	baseURL         string
	institutionCode string
	signingKey      *rsa.PrivateKey
	desKey          []byte
	httpClient      *http.Client
}

type ClientConfig struct {
	BaseURL         string
	InstitutionCode string
	SigningKeyPEM   []byte
	DESKeyB64       string
	Timeout         time.Duration
}

func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("nibss: base URL required")
	}
	if cfg.InstitutionCode == "" {
		return nil, fmt.Errorf("nibss: institution code required")
	}
	if len(cfg.SigningKeyPEM) == 0 {
		return nil, fmt.Errorf("nibss: signing key required")
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	return &Client{
		baseURL:         cfg.BaseURL,
		institutionCode: cfg.InstitutionCode,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		},
	}, nil
}

func (c *Client) Mode() string { return "real" }

func (c *Client) Transfer(ctx context.Context,
	req TransferRequest) (*TransferResponse, error) {
	return nil, ErrNotImplemented
}

func (c *Client) NameEnquiry(ctx context.Context,
	req NameEnquiryRequest) (*NameEnquiryResponse, error) {
	return nil, ErrNotImplemented
}

var (
	_ Provider = (*Client)(nil)
	_ Provider = (*DummyClient)(nil)
)
