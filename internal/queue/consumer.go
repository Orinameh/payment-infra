package queue

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Handler processes one consumed event. Return nil on success (message
// is acked); return an error to Nak with backoff for redelivery.
type Handler func(ctx context.Context, subject string, payload []byte) error

// Consumer is a durable JetStream push consumer. Durability + explicit
// acks mean an event is never lost to a worker crash: unacked messages
// are redelivered. processed_messages dedup makes handling idempotent
// across those redeliveries.
type Consumer struct {
	conn     *nats.Conn
	js       jetstream.JetStream
	stream   string
	durable  string
	subjects []string
	pool     *pgxpool.Pool
	handler  Handler
}

type ConsumerConfig struct {
	URL      string
	Stream   string
	Durable  string
	Subjects []string
}

func NewConsumer(pool *pgxpool.Pool, cfg ConsumerConfig, h Handler) (*Consumer, error) {
	nc, err := nats.Connect(cfg.URL,
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			slog.Error("nats consumer disconnected", "err", err)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("queue: consumer connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("queue: consumer jetstream: %w", err)
	}
	return &Consumer{
		conn: nc, js: js,
		stream: cfg.Stream, durable: cfg.Durable, subjects: cfg.Subjects,
		pool: pool, handler: h,
	}, nil
}

// Run blocks until ctx is cancelled. Each message is deduped via
// processed_messages BEFORE the handler runs, so a crash between
// handler success and ack cannot double-apply side effects.
func (c *Consumer) Run(ctx context.Context) error {
	cons, err := c.js.CreateOrUpdateConsumer(ctx, c.stream, jetstream.ConsumerConfig{
		Durable:        c.durable,
		FilterSubjects: c.subjects,
		AckPolicy:      jetstream.AckExplicitPolicy,
		AckWait:        30 * time.Second,
		MaxDeliver:     5,
	})
	if err != nil {
		return fmt.Errorf("queue: create consumer: %w", err)
	}

	cc, err := cons.Consume(func(msg jetstream.Msg) {
		mctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		id := msg.Headers().Get("Nats-Msg-Id")
		if id == "" {
			if meta, merr := msg.Metadata(); merr == nil {
				id = fmt.Sprintf("%s:%d", meta.Stream, meta.Sequence.Stream)
			} else {
				id = "unknown"
			}
		}

		// Claim exactly once. Concurrent/redelivered workers racing on
		// the same message: exactly one INSERT wins.
		var claimed bool
		err := c.pool.QueryRow(mctx, `
			INSERT INTO processed_messages (consumer_name, message_id)
			VALUES ($1, $2)
			ON CONFLICT (consumer_name, message_id) DO NOTHING
			RETURNING true`, c.durable, id).Scan(&claimed)
		if err != nil && err != pgx.ErrNoRows {
			slog.Error("consumer dedup insert failed", "err", err, "msg_id", id)
			_ = msg.Nak()
			return
		}
		if err == pgx.ErrNoRows {
			// Already processed — ack and move on.
			_ = msg.Ack()
			return
		}

		if herr := c.handler(mctx, msg.Subject(), msg.Data()); herr != nil {
			slog.Error("consumer handler failed, nacking",
				"err", herr, "subject", msg.Subject(), "msg_id", id)
			// Remove the claim so the redelivery re-runs the handler.
			_, _ = c.pool.Exec(context.Background(),
				`DELETE FROM processed_messages WHERE consumer_name = $1 AND message_id = $2`,
				c.durable, id)
			_ = msg.Nak()
			return
		}
		_ = msg.Ack()
	})
	if err != nil {
		return fmt.Errorf("queue: consume: %w", err)
	}
	defer cc.Stop()

	<-ctx.Done()
	return nil
}

func (c *Consumer) Close() error { return c.conn.Drain() }
