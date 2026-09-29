package queue

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type NATSConfig struct {
	URL        string
	StreamName string
	Subjects   []string
	MaxAge     time.Duration
	MaxBytes   int64
	Replicas   int
}

type Publisher struct {
	conn *nats.Conn
	js   jetstream.JetStream
}

func NewPublisher(ctx context.Context, cfg NATSConfig) (*Publisher, error) {
	nc, err := nats.Connect(cfg.URL,
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			slog.Error("nats disconnected", "err", err)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("queue: connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("queue: jetstream: %w", err)
	}
	_, err = js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:      cfg.StreamName,
		Subjects:  cfg.Subjects,
		Retention: jetstream.LimitsPolicy,
		MaxAge:    cfg.MaxAge,
		MaxBytes:  cfg.MaxBytes,
		Storage:   jetstream.FileStorage,
		Replicas:  cfg.Replicas,
	})
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("queue: stream: %w", err)
	}
	return &Publisher{conn: nc, js: js}, nil
}

func (p *Publisher) Publish(ctx context.Context, subject, key string, payload []byte) error {
	_, err := p.js.Publish(ctx, subject, payload, jetstream.WithMsgID(key))
	if err != nil {
		return fmt.Errorf("queue: publish %s: %w", subject, err)
	}
	return nil
}

func (p *Publisher) Close() error { return p.conn.Drain() }
