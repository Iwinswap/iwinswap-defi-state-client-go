package types

import (
	"math/big"

	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/poolregistry"
	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/tokensystem"
	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/uniswapv2"
	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/uniswapv3"
	"github.com/ethereum/go-ethereum/common"
)

// --------------------------------------------------------------------------------
// --- Interfaces and View Models ---
// --------------------------------------------------------------------------------

// --- Block-Aware Subsystem Interfaces ---

type ProtocolName string

type UniswapV2Subsystem interface {
	View() []uniswapv2.PoolView
	LastUpdatedAtBlock() uint64
}

type UniswapV3Subsystem interface {
	View() []uniswapv3.PoolView
	LastUpdatedAtBlock() uint64
}

type UniswapV4Subsystem interface {
	View() any
	LastUpdatedAtBlock() uint64
}

type BalancerV2Subsystem interface {
	View() any
	LastUpdatedAtBlock() uint64
}

type BalancerV3Subsystem interface {
	View() any
	LastUpdatedAtBlock() uint64
}

type PoolRegistrySubsystem interface {
	View() []poolregistry.PoolView
}

type TokenPoolSubsystem interface {
	View() *poolregistry.TokenPoolsRegistryView
}

type TokenSubsystem interface {
	View() []tokensystem.TokenView
}

// Logger defines a standard interface for structured, leveled logging,
// compatible with the standard library's slog.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

type UniswapV2SubsystemsResult struct {
	Data  map[ProtocolName][]uniswapv2.PoolView `json:"data,omitempty"`
	Error map[ProtocolName]string               `json:"error,omitempty"`
}

type UniswapV3SubsystemsResult struct {
	Data  map[ProtocolName][]uniswapv3.PoolView `json:"data,omitempty"`
	Error map[ProtocolName]string               `json:"error,omitempty"`
}

type UniswapV4SubsystemsResult struct {
	Data  map[ProtocolName]any    `json:"data,omitempty"`
	Error map[ProtocolName]string `json:"error,omitempty"`
}

type BalancerV2SubsystemsResult struct {
	Data  map[ProtocolName]any    `json:"data,omitempty"`
	Error map[ProtocolName]string `json:"error,omitempty"`
}

type BalancerV3SubsystemsResult struct {
	Data  map[ProtocolName]any    `json:"data,omitempty"`
	Error map[ProtocolName]string `json:"error,omitempty"`
}

type PoolRegistrySubsystemResult struct {
	Data  []poolregistry.PoolView `json:"data,omitempty"`
	Error string                  `json:"error,omitempty"`
}

type TokenPoolSubsystemResult struct {
	Data  *poolregistry.TokenPoolsRegistryView `json:"data,omitempty"`
	Error string                               `json:"error,omitempty"`
}

type TokenSubsystemResult struct {
	Data  []tokensystem.TokenView `json:"data,omitempty"`
	Error string                  `json:"error,omitempty"`
}

// SubsystemView holds the result from all configured subsystems for a given block.
type SubsystemView struct {
	// DeFi Protocols Subsystems
	UniswapV2  UniswapV2SubsystemsResult  `json:"uniswapV2"`
	UniswapV3  UniswapV3SubsystemsResult  `json:"uniswapV3"`
	UniswapV4  UniswapV4SubsystemsResult  `json:"uniswapV4"`
	BalancerV2 BalancerV2SubsystemsResult `json:"balancerV2"`
	BalancerV3 BalancerV3SubsystemsResult `json:"balancerV3"`

	// Low level Subsystems
	PoolRegistry    PoolRegistrySubsystemResult `json:"poolRegistry"`
	TokenPoolSystem TokenPoolSubsystemResult    `json:"tokenPoolSystem"`
	TokenSystem     TokenSubsystemResult        `json:"tokenSystem"`
}

func (sv *SubsystemView) HasErrors() bool {
	return len(sv.UniswapV2.Error) > 0 ||
		len(sv.UniswapV3.Error) > 0 ||
		len(sv.UniswapV4.Error) > 0 ||
		len(sv.BalancerV2.Error) > 0 ||
		len(sv.BalancerV3.Error) > 0 ||
		sv.PoolRegistry.Error != "" ||
		sv.TokenSystem.Error != "" ||
		sv.TokenPoolSystem.Error != ""
}

// BlockSummary contains only the essential block information for clients.
type BlockSummary struct {
	Number      *big.Int    `json:"number"`
	Hash        common.Hash `json:"hash"`
	Timestamp   uint64      `json:"timestamp"`
	ReceivedAt  int64       `json:"receivedAt"` // The Unix nanosecond timestamp when the engine started processing the block.
	GasUsed     uint64      `json:"gasUsed"`
	GasLimit    uint64      `json:"gasLimit"`
	StateRoot   common.Hash `json:"stateRoot"`
	TxHash      common.Hash `json:"txHash"`
	ReceiptHash common.Hash `json:"receiptHash"`
}

// DefiStateEngineView is the main data structure broadcast to subscribers.
type DefiStateEngineView struct {
	ChainID    uint64        `json:"chainId"`
	Timestamp  uint64        `json:"timestamp"`
	Block      BlockSummary  `json:"block"`
	Subsystems SubsystemView `json:"subsystems"`
}

// Subscription represents a subscription to the DefiStateEngine's event stream.
type Subscription struct {
	// done is the internal channel that will be closed when the engine shuts down.
	done <-chan struct{}

	c <-chan *DefiStateEngineView
}

// C provides a public getter for the DefiStateEngineView c chan
// getter for the event channel and bridging its concrete type.
func (s *Subscription) C() <-chan *DefiStateEngineView {
	return s.c
}

// Done provides a public getter for the shutdown signal channel.
func (s *Subscription) Done() <-chan struct{} {
	return s.done
}

func NewSubscription(c <-chan *DefiStateEngineView, done <-chan struct{}) *Subscription {
	return &Subscription{
		c:    c,
		done: done,
	}
}

type UniswapV2SubsystemDiffer func(old, new []uniswapv2.PoolView) UniswapV2SubsystemDiff
type UniswapV3SubsystemDiffer func(old, new []uniswapv3.PoolView) UniswapV3SubsystemDiff
type UniswapV4SubsystemDiffer func(old, new any) UniswapV4SubsystemDiff
type BalancerV2SubsystemDiffer func(old, new any) BalancerV2SubsystemDiff
type BalancerV3SubsystemDiffer func(old, new any) BalancerV3SubsystemDiff
type PoolRegistrySubsystemDiffer func(old, new []poolregistry.PoolView) PoolRegistrySubsystemDiff
type TokenPoolSubsystemDiffer func(old, new *poolregistry.TokenPoolsRegistryView) TokenPoolSubsystemDiff
type TokenSubsystemDiffer func(old, new []tokensystem.TokenView) TokenSubsystemDiff

// --- Diff Structures with Helper Methods ---

type UniswapV2SubsystemDiff struct {
	Additions []uniswapv2.PoolView `json:"additions,omitempty"`
	Updates   []uniswapv2.PoolView `json:"updates,omitempty"`
	Deletions []uint64             `json:"deletions,omitempty"`
}

// IsEmpty returns true if the diff contains no changes.
func (d UniswapV2SubsystemDiff) IsEmpty() bool {
	return len(d.Additions) == 0 && len(d.Updates) == 0 && len(d.Deletions) == 0
}

type UniswapV3SubsystemDiff struct {
	Additions []uniswapv3.PoolView `json:"additions,omitempty"`
	Updates   []uniswapv3.PoolView `json:"updates,omitempty"`
	Deletions []uint64             `json:"deletions,omitempty"`
}

// IsEmpty returns true if the diff contains no changes.
func (d UniswapV3SubsystemDiff) IsEmpty() bool {
	return len(d.Additions) == 0 && len(d.Updates) == 0 && len(d.Deletions) == 0
}

type UniswapV4SubsystemDiff struct {
	Data any `json:"data,omitempty"`
}

// IsEmpty returns true if the diff contains no data.
func (d UniswapV4SubsystemDiff) IsEmpty() bool {
	return d.Data == nil
}

type BalancerV2SubsystemDiff struct {
	Data any `json:"data,omitempty"`
}

// IsEmpty returns true if the diff contains no data.
func (d BalancerV2SubsystemDiff) IsEmpty() bool {
	return d.Data == nil
}

type BalancerV3SubsystemDiff struct {
	Data any `json:"data,omitempty"`
}

// IsEmpty returns true if the diff contains no data.
func (d BalancerV3SubsystemDiff) IsEmpty() bool {
	return d.Data == nil
}

type PoolRegistrySubsystemDiff struct {
	Additions []poolregistry.PoolView `json:"additions,omitempty"`
	Deletions []uint64                `json:"deletions,omitempty"`
}

// IsEmpty returns true if the diff contains no changes.
func (d PoolRegistrySubsystemDiff) IsEmpty() bool {
	return len(d.Additions) == 0 && len(d.Deletions) == 0
}

type TokenPoolSubsystemDiff struct {
	Data *poolregistry.TokenPoolsRegistryView `json:"data,omitempty"`
}

// IsEmpty returns true if the diff contains no data.
func (d TokenPoolSubsystemDiff) IsEmpty() bool {
	return d.Data == nil
}

type TokenSubsystemDiff struct {
	Additions []tokensystem.TokenView `json:"additions,omitempty"`
	Updates   []tokensystem.TokenView `json:"updates,omitempty"`
	Deletions []uint64                `json:"deletions,omitempty"`
}

// IsEmpty returns true if the diff contains no changes.
func (d TokenSubsystemDiff) IsEmpty() bool {
	return len(d.Additions) == 0 && len(d.Updates) == 0 && len(d.Deletions) == 0
}

// SubsystemDiffView holds the diff from all configured subsystems for a given block.
type SubsystemDiffView struct {
	// DeFi Protocols Subsystems
	UniswapV2  map[ProtocolName]UniswapV2SubsystemDiff  `json:"uniswapV2"`
	UniswapV3  map[ProtocolName]UniswapV3SubsystemDiff  `json:"uniswapV3"`
	UniswapV4  map[ProtocolName]UniswapV4SubsystemDiff  `json:"uniswapV4"`
	BalancerV2 map[ProtocolName]BalancerV2SubsystemDiff `json:"balancerV2"`
	BalancerV3 map[ProtocolName]BalancerV3SubsystemDiff `json:"balancerV3"`

	// Low level Subsystems
	TokenSystem     TokenSubsystemDiff        `json:"tokenSystem"`
	PoolRegistry    PoolRegistrySubsystemDiff `json:"poolRegistry"`
	TokenPoolSystem TokenPoolSubsystemDiff    `json:"tokenPoolSystem"`
}

// --- High-Level Helper Methods for SubsystemDiffView ---

// IsUniswapV2DiffAvailable returns true if there are any diffs for any Uniswap V2 forks.
func (sdv *SubsystemDiffView) IsUniswapV2DiffAvailable() bool {
	return len(sdv.UniswapV2) > 0
}

// IsUniswapV3DiffAvailable returns true if there are any diffs for any Uniswap V3 forks.
func (sdv *SubsystemDiffView) IsUniswapV3DiffAvailable() bool {
	return len(sdv.UniswapV3) > 0
}

// IsTokenSystemDiffAvailable returns true if the token system diff is not empty.
func (sdv *SubsystemDiffView) IsTokenSystemDiffAvailable() bool {
	return !sdv.TokenSystem.IsEmpty()
}

// IsPoolRegistryDiffAvailable returns true if the pool registry diff is not empty.
func (sdv *SubsystemDiffView) IsPoolRegistryDiffAvailable() bool {
	return !sdv.PoolRegistry.IsEmpty()
}

// IsTokenPoolSystemDiffAvailable returns true if the token pool system diff is not empty.
func (sdv *SubsystemDiffView) IsTokenPoolSystemDiffAvailable() bool {
	return !sdv.TokenPoolSystem.IsEmpty()
}

// IsEmpty returns true if no subsystems have any diffs available.
func (sdv *SubsystemDiffView) IsEmpty() bool {
	return !sdv.IsUniswapV2DiffAvailable() &&
		!sdv.IsUniswapV3DiffAvailable() &&
		len(sdv.UniswapV4) == 0 && // Check placeholders directly
		len(sdv.BalancerV2) == 0 &&
		len(sdv.BalancerV3) == 0 &&
		!sdv.IsTokenSystemDiffAvailable() &&
		!sdv.IsPoolRegistryDiffAvailable() &&
		!sdv.IsTokenPoolSystemDiffAvailable()
}

// DefiStateEngineDiffView represents a summary of changes FromBlock to ToBlock.
type DefiStateEngineDiffView struct {
	Timestamp  uint64            `json:"timestamp"`
	FromBlock  uint64            `json:"fromBlock"`
	ToBlock    BlockSummary      `json:"toBlock"`
	Subsystems SubsystemDiffView `json:"subsystems,omitempty"`
}
