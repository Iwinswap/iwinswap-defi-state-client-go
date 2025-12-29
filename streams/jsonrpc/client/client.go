package client

//@note We used to think the Engine was the "thing", but the client is everything
// how can we make every client easy to use, with data accessible in the simplest way?
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	differ "github.com/defistate/defi-state-client-go/differ"
	"github.com/defistate/defi-state-client-go/engine"
	"github.com/ethereum/go-ethereum/rpc"
)

// Constants for reconnection logic
const (
	initialReconnectDelay = 1 * time.Second
	maxReconnectDelay     = 30 * time.Second

	// RpcNamespace is the namespace under which the streamer is registered.
	RpcNamespace                  = "defi"
	StateStreamSubscriptionMethod = "subscribeStateStream"
)

// Logger defines a standard interface for structured, leveled logging.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// StatePatcherFunc defines the function signature for a method that safely applies
// a diff to a previous state.
type StatePatcherFunc func(prevState *engine.State, diff *differ.StateDiff) (newState *engine.State, err error)

type DecoderFunc func(schema engine.ProtocolSchema, data json.RawMessage) (any, error)

// Config holds the configuration for the client.
type Config struct {
	URL              string
	Logger           Logger
	BufferSize       uint
	StatePatcher     StatePatcherFunc
	StateDecoder     DecoderFunc
	StateDiffDecoder DecoderFunc
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
	if c.StateDecoder == nil {
		return errors.New("config: StateDecoder is required")
	}
	if c.StateDiffDecoder == nil {
		return errors.New("config: StateDiffDecoder is required")
	}
	return nil
}

// Client manages the connection and subscription to the DeFi State Engine.
type Client struct {
	lastState        *engine.State
	statePatcher     StatePatcherFunc
	stateDecoder     DecoderFunc
	stateDiffDecoder DecoderFunc
	stateCh          chan *engine.State
	errCh            chan error
	logger           Logger
}

// SubscriptionEvent is the wrapper object received from the server.
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
		stateCh:          make(chan *engine.State, cfg.BufferSize),
		statePatcher:     cfg.StatePatcher,
		stateDecoder:     cfg.StateDecoder,
		stateDiffDecoder: cfg.StateDiffDecoder,
		errCh:            make(chan error, 1),
		logger:           cfg.Logger,
	}

	go client.run(ctx, cfg.URL)
	return client, nil
}

// State returns a read-only channel for receiving new states.
func (c *Client) State() <-chan *engine.State {
	return c.stateCh
}

// Err returns a read-only channel for receiving fatal (unrecoverable) errors.
func (c *Client) Err() <-chan error {
	return c.errCh
}

// run handles the entire lifecycle of the client, including reconnection.
func (c *Client) run(ctx context.Context, url string) {
	defer close(c.stateCh)
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
		reconnectDelay = initialReconnectDelay // Reset delay on success

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
	sub, err := rpcClient.Subscribe(ctx, RpcNamespace, rawCh, StateStreamSubscriptionMethod)
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
		var (
			cState clientState
		)
		if err := json.Unmarshal(event.Payload, &cState); err != nil {
			c.logger.Error("Failed to unmarshal full state payload", "error", err)
			return
		}

		// init state
		state := engine.State{
			ChainID:   cState.ChainID,
			Timestamp: cState.Timestamp,
			Block:     cState.Block,
			Protocols: map[engine.ProtocolID]engine.ProtocolState{},
		}

		for pID, protocolState := range cState.Protocols {
			// get the actual typed data from raw message
			typedData, err := c.stateDecoder(protocolState.Schema, protocolState.Data)
			if err != nil {
				// @todo maybe return partial state with errors?
				c.logger.Error("Failed to decode state", "error", err)
				return
			}

			state.Protocols[pID] = engine.ProtocolState{
				Meta:              protocolState.Meta,
				SyncedBlockNumber: protocolState.SyncedBlockNumber,
				Schema:            protocolState.Schema,
				Data:              typedData,
				Error:             protocolState.Error,
			}

		}

		clientProcessingDur := time.Since(clientProcessingStart)
		c.logMetrics(&state, clientProcessingDur, event.SentAt, "full")

		c.storeState(&state)
		c.stateCh <- &state

	case "diff":
		var cDiff clientStateDiff
		if err := json.Unmarshal(event.Payload, &cDiff); err != nil {
			c.logger.Error("Failed to unmarshal diff payload", "error", err)
			return
		}

		if c.lastState == nil {
			c.logger.Warn("Received a diff before any full state was processed; discarding.", "from_block", cDiff.FromBlock, "to_block", cDiff.ToBlock.Number)
			return
		}

		// create stateDiff
		diff := differ.StateDiff{
			FromBlock: cDiff.FromBlock,
			ToBlock:   cDiff.ToBlock,
			Timestamp: cDiff.Timestamp,
			Protocols: make(map[engine.ProtocolID]differ.ProtocolDiff),
		}

		for pID, protocolDiff := range cDiff.Protocols {
			// get the actual typed data from raw message
			typedData, err := c.stateDiffDecoder(protocolDiff.Schema, protocolDiff.Data)
			if err != nil {
				c.logger.Error("Failed to decode state", "error", err)
				return
			}

			diff.Protocols[pID] = differ.ProtocolDiff{
				Meta:              protocolDiff.Meta,
				SyncedBlockNumber: protocolDiff.SyncedBlockNumber,
				Schema:            protocolDiff.Schema,
				Data:              typedData,
				Error:             protocolDiff.Error,
			}

		}

		lastBlockNum := c.lastState.Block.Number.Uint64()
		if diff.FromBlock != lastBlockNum {
			c.logger.Warn(
				"Received out-of-order diff; state may be out of sync. Discarding diff and waiting for a full state to self-heal.",
				"last_known_block", lastBlockNum,
				"diff_from_block", diff.FromBlock,
				"diff_to_block", diff.ToBlock.Number,
			)
			return
		}

		// Apply patch
		newState, err := c.statePatcher(c.lastState, &diff)
		if err != nil {
			c.logger.Error("Failed to construct full state from diff", "error", err)
			return
		}

		// Ensure the new state timestamp reflects the diff's generation time
		newState.Timestamp = diff.Timestamp

		clientProcessingDur := time.Since(clientProcessingStart)
		c.logMetrics(newState, clientProcessingDur, event.SentAt, "diff")

		c.storeState(newState)
		c.stateCh <- newState

	default:
		c.logger.Warn("Received unknown event type", "type", event.Type)
	}
}

func (c *Client) storeState(state *engine.State) {
	c.lastState = state
}

// logMetrics calculates and logs key performance indicators using the new generic structure.
func (c *Client) logMetrics(state *engine.State, clientProcessingDur time.Duration, sentAt int64, stateType string) {
	if state == nil {
		c.logger.Warn("logMetrics called with a nil state")
		return
	}

	// --- Define Time Points ---
	clientFinishTime := time.Now()                                // T5
	blockTimestamp := time.Unix(int64(state.Block.Timestamp), 0)  // T1
	clientStartTime := clientFinishTime.Add(-clientProcessingDur) // T4
	serverFinishTime := time.Unix(0, sentAt)                      // T3 (direct from server)

	// --- Calculations ---
	transportTime := clientStartTime.Sub(serverFinishTime) // T4 - T3
	totalLatency := clientFinishTime.Sub(blockTimestamp)   // T5 - T1
	serverProcessingMs := serverFinishTime.Sub(time.Unix(0, state.Block.ReceivedAt)).Milliseconds()

	// --- Generic Protocol Summary ---
	// Instead of hardcoding "Uniswap" or "TokenSystem", we count everything generically.
	protocolCount := len(state.Protocols)
	errorCount := 0

	// We can add a simple breakdown if needed, but keeping it light for high-frequency logs.
	for _, p := range state.Protocols {
		if p.Error != "" {
			errorCount++
		}
	}

	logAttrs := []any{
		"block_number", state.Block.Number,
		"state_type", stateType,
		"protocols_total", protocolCount,
		"protocols_with_errors", errorCount,
		"total_latency_ms", totalLatency.Round(time.Millisecond).Milliseconds(),
		"transport_ms", transportTime.Round(time.Millisecond).Milliseconds(),
		"client_processing_ms", clientProcessingDur.Round(time.Microsecond).Milliseconds(),
		"server_processing_ms", serverProcessingMs,
	}

	c.logger.Debug("Received new state", logAttrs...)
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
