package cache

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// CachedWallet is the JSON document stored in Redis. It mirrors the
// fields the read path needs (balance display + ownership check).
// Ownership (user_id) is immutable, so serving it from cache is safe.
type CachedWallet struct {
	ID       uuid.UUID `json:"id"`
	UserID   uuid.UUID `json:"user_id"`
	Currency string    `json:"currency"`
	Balance  int64     `json:"balance_minor"`
	Version  int64     `json:"version"`
	Status   string    `json:"status"`
}

func walletKey(id uuid.UUID) string { return "wallet:" + id.String() }

// WalletCache is a cache-aside balance cache. PostgreSQL is the source
// of truth; Redis only absorbs repeat balance reads. Entries are
// invalidated on every write (best-effort Del — a missed invalidation
// self-heals at TTL expiry) and expire after ttl regardless.
type WalletCache struct {
	client *redis.Client
	ttl    time.Duration
}

func NewWalletCache(client *redis.Client) *WalletCache {
	return &WalletCache{client: client, ttl: 15 * time.Second}
}

func (c *WalletCache) GetWallet(ctx context.Context, id uuid.UUID) (*CachedWallet, bool) {
	raw, err := c.client.Get(ctx, walletKey(id)).Bytes()
	if err != nil {
		return nil, false
	}
	var w CachedWallet
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, false
	}
	return &w, true
}

func (c *WalletCache) SetWallet(ctx context.Context, w *CachedWallet) {
	raw, err := json.Marshal(w)
	if err != nil {
		return
	}
	_ = c.client.Set(ctx, walletKey(w.ID), raw, c.ttl).Err()
}

func (c *WalletCache) DelWallets(ctx context.Context, ids ...uuid.UUID) {
	if len(ids) == 0 {
		return
	}
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = walletKey(id)
	}
	_ = c.client.Del(ctx, keys...).Err()
}
