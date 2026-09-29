package cache

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Config struct {
	Addr          string
	Password      string
	DB            int
	PoolSize      int
	MinIdleConns  int
	DialTimeout   time.Duration
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	TLSEnabled    bool
	TLSSkipVerify bool
}

func Connect(ctx context.Context, cfg Config) (*redis.Client, error) {
	opts := &redis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}
	if cfg.TLSEnabled {
		opts.TLSConfig = &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: cfg.TLSSkipVerify,
		}
	}
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("cache: ping: %w", err)
	}
	return client, nil
}

// Lock provides distributed mutual exclusion across processes.
type Lock struct{ client *redis.Client }

func NewLock(client *redis.Client) *Lock { return &Lock{client: client} }

var ErrLockNotAcquired = errors.New("cache: lock not acquired")

var releaseScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
else
    return 0
end`)

func (l *Lock) Acquire(ctx context.Context, key string, ttl time.Duration) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	ok, err := l.client.SetNX(ctx, "lock:"+key, token, ttl).Result()
	if err != nil {
		return "", fmt.Errorf("cache: acquire: %w", err)
	}
	if !ok {
		return "", ErrLockNotAcquired
	}
	return token, nil
}

func (l *Lock) Release(ctx context.Context, key, token string) error {
	_, err := releaseScript.Run(ctx, l.client, []string{"lock:" + key}, token).Result()
	return err
}

func (l *Lock) WithLock(ctx context.Context, key string, ttl time.Duration, fn func(context.Context) error) error {
	token, err := l.Acquire(ctx, key, ttl)
	if err != nil {
		return err
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = l.Release(rctx, key, token)
	}()
	return fn(ctx)
}
