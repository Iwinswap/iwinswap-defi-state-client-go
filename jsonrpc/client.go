package jsonrpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Iwinswap/iwinswap-defi-state-client-go/types"
	"github.com/ethereum/go-ethereum/rpc"
)

// Constants for RPC subscription
const (
	rpcNamespace = "defi"
	rpcMethod    = "subscribeDefiViews"
)

// Constants for reconnection logic
const (
	initialReconnectDelay = 1 * time.Second
	maxReconnectDelay     = 30 * time.Second
	maxStoredPrevViews    = 10
)

// Logger defines a standard interface for structured, leveled logging.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// StatePatcherFunc defines the function signature for a method that safely applies
// a diff to a previous state view. Implementations must ensure they do not mutate
// the provided 'prevView' and instead return a completely new state view.
type StatePatcherFunc func(prevView *types.DefiStateEngineView, diff *types.DefiStateEngineDiffView) (newView *types.DefiStateEngineView, err error)

// Config holds the configuration for the client.
type Config struct {
	URL          string
	Logger       Logger
	BufferSize   uint
	StatePatcher StatePatcherFunc
}

// validate checks if the configuration is valid.
func (c *Config) validate() error {
	if c.URL == "" {
		return errors.New("config: URL is required")
	}
	if c.BufferSize < 1 {
		return errors.New("config: BufferSize must be greater than 0")
	}
	if c.Logger == nil {
		return errors.New("config: Logger is required")
	}
	if c.StatePatcher == nil {
		return errors.New("config: StatePatcher is required")
	}
	return nil
}

// Client manages the connection and subscription to the DeFi State Engine.
type Client struct {
	lastView     *types.DefiStateEngineView
	statePatcher StatePatcherFunc
	viewCh       chan *types.DefiStateEngineView
	errCh        chan error
	logger       Logger
}

// SubscriptionEvent is the wrapper object received from the server.
// It now includes a SentAt timestamp for accurate transport time measurement.
type SubscriptionEvent struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
	SentAt  int64           `json:"sentAt"`
}

// NewClient creates a new client and starts the connection and subscription manager.
func NewClient(ctx context.Context, cfg Config) (*Client, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	client := &Client{
		viewCh:       make(chan *types.DefiStateEngineView, cfg.BufferSize),
		statePatcher: cfg.StatePatcher,
		errCh:        make(chan error, 1),
		logger:       cfg.Logger,
	}

	go client.run(ctx, cfg.URL)
	return client, nil
}

// View returns a read-only channel for receiving new state views.
func (c *Client) View() <-chan *types.DefiStateEngineView {
	return c.viewCh
}

// Err returns a read-only channel for receiving fatal (unrecoverable) errors.
func (c *Client) Err() <-chan error {
	return c.errCh
}

// run handles the entire lifecycle of the client, including reconnection.
func (c *Client) run(ctx context.Context, url string) {
	defer close(c.viewCh)
	defer close(c.errCh)
	reconnectDelay := initialReconnectDelay
	for {
		if ctx.Err() != nil {
			c.logger.Info("Client context canceled, shutting down.")
			return
		}
		c.logger.Info("Attempting to connect to RPC server", "url", url)
		rpcClient, err := rpc.DialContext(ctx, url)
		if err != nil {
			c.logger.Error("Failed to connect to RPC server, will retry...", "error", err, "delay", reconnectDelay)
			time.Sleep(reconnectDelay)
			reconnectDelay = min(reconnectDelay*2, maxReconnectDelay)
			continue
		}
		c.logger.Info("Successfully connected to RPC server.")
		reconnectDelay = initialReconnectDelay
		err = c.subscribeAndProcess(ctx, rpcClient)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				c.logger.Info("Context canceled during subscription, shutting down.", "error", err)
				return
			}
			c.logger.Error("Subscription failed, will reconnect...", "error", err, "delay", reconnectDelay)
			time.Sleep(reconnectDelay)
			reconnectDelay = min(reconnectDelay*2, maxReconnectDelay)
		}
	}
}

// subscribeAndProcess handles the subscription and processing of messages.
func (c *Client) subscribeAndProcess(ctx context.Context, rpcClient *rpc.Client) error {
	defer rpcClient.Close()
	rawCh := make(chan json.RawMessage)
	sub, err := rpcClient.Subscribe(ctx, rpcNamespace, rawCh, rpcMethod)
	if err != nil {
		return fmt.Errorf("failed to subscribe: %w", err)
	}
	defer sub.Unsubscribe()
	c.logger.Info("Successfully subscribed. Waiting for data...")
	for {
		select {
		case rawData := <-rawCh:
			c.processMessage(rawData)
		case err := <-sub.Err():
			return err
		case <-ctx.Done():
			c.logger.Info("Context cancelled, stopping subscription.")
			return ctx.Err()
		}
	}
}

// processMessage handles unmarshalling and routing of incoming server events.
func (c *Client) processMessage(rawData json.RawMessage) {
	clientProcessingStart := time.Now()
	var event SubscriptionEvent
	if err := json.Unmarshal(rawData, &event); err != nil {
		c.logger.Error("Failed to unmarshal subscription event", "error", err)
		return
	}

	switch event.Type {
	case "full":
		var view types.DefiStateEngineView
		if err := json.Unmarshal(event.Payload, &view); err != nil {
			c.logger.Error("Failed to unmarshal full view payload", "error", err)
			return
		}
		clientProcessingDur := time.Since(clientProcessingStart)
		c.logMetrics(&view, clientProcessingDur, event.SentAt, "full")
		c.storeView(&view)
		c.viewCh <- &view

	case "diff":
		var diff types.DefiStateEngineDiffView
		if err := json.Unmarshal(event.Payload, &diff); err != nil {
			c.logger.Error("Failed to unmarshal diff payload", "error", err)
			return
		}

		if c.lastView == nil {
			c.logger.Warn("Received a diff before any full view was processed; discarding.", "from_block", diff.FromBlock, "to_block", diff.ToBlock.Number)
			return
		}

		lastBlockNum := c.lastView.Block.Number.Uint64()
		if diff.FromBlock != lastBlockNum {
			c.logger.Warn(
				"Received out-of-order diff; state may be out of sync. Discarding diff and waiting for a full view to self-heal.",
				"last_known_block", lastBlockNum,
				"diff_from_block", diff.FromBlock,
				"diff_to_block", diff.ToBlock.Number,
			)
			return
		}

		view, err := c.statePatcher(c.lastView, &diff)
		if err != nil {
			c.logger.Error("Failed to construct full view from diff", "error", err)
			return
		}

		// Set the server's diff processing time on the client-reconstructed view.
		view.Timestamp = diff.Timestamp

		clientProcessingDur := time.Since(clientProcessingStart)
		c.logMetrics(view, clientProcessingDur, event.SentAt, "diff")
		c.storeView(view)
		c.viewCh <- view

	default:
		c.logger.Warn("Received unknown event type", "type", event.Type)
	}
}

// storeView updates the last known view.
func (c *Client) storeView(view *types.DefiStateEngineView) {
	c.lastView = view
}

// logMetrics calculates and logs key performance indicators, now including the view type.
func (c *Client) logMetrics(view *types.DefiStateEngineView, clientProcessingDur time.Duration, sentAt int64, viewType string) {
	if view == nil {
		c.logger.Warn("logMetrics called with a nil view ")
		return
	}

	// --- Define Time Points ---
	clientFinishTime := time.Now()                                // T5
	blockTimestamp := time.Unix(int64(view.Block.Timestamp), 0)   // T1
	clientStartTime := clientFinishTime.Add(-clientProcessingDur) // T4
	serverFinishTime := time.Unix(0, sentAt)                      // T3 (direct from server)

	// --- Perform New, More Accurate Calculations ---
	transportTime := clientStartTime.Sub(serverFinishTime) // T4 - T3
	totalLatency := clientFinishTime.Sub(blockTimestamp)   // T5 - T1

	logAttrs := []any{
		"block_number", view.Block.Number,
		"view_type", viewType,
		"tokens", len(view.Subsystems.TokenSystem.Data),
		"pools", len(view.Subsystems.PoolRegistry.Data),
		"uniswap_v2_pools", len(view.Subsystems.UniswapV2.Data),
		"uniswap_v3_pools", len(view.Subsystems.UniswapV3.Data),
		"total_latency_ms", totalLatency.Round(time.Millisecond).Milliseconds(),
		"transport_ms", transportTime.Round(time.Millisecond).Milliseconds(),
		"client_processing_ms", clientProcessingDur.Round(time.Microsecond).Milliseconds(),
		"server_processing_ms", serverFinishTime.Sub(time.Unix(0, int64(view.Block.ReceivedAt))).Milliseconds(),
	}

	c.logger.Info("Received new state view", logAttrs...)
}
