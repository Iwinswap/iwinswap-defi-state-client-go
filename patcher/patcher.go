package patcher

import (
	"errors"
	"fmt"

	"github.com/Iwinswap/iwinswap-defi-state-client-go/types"
	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/poolregistry"
	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/tokensystem"
	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/uniswapv2"
	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/uniswapv3"
)

// --- Type Definitions ---

// Logger defines a standard interface for structured, leveled logging.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// --- Individual Patcher & Copier Function Types ---

type UniswapV2SubsystemPatcher func(prevState []uniswapv2.PoolView, diff types.UniswapV2SubsystemDiff) ([]uniswapv2.PoolView, error)
type UniswapV3SubsystemPatcher func(prevState []uniswapv3.PoolView, diff types.UniswapV3SubsystemDiff) ([]uniswapv3.PoolView, error)
type PoolRegistrySubsystemPatcher func(prevState []poolregistry.PoolView, diff types.PoolRegistrySubsystemDiff) ([]poolregistry.PoolView, error)
type TokenSubsystemPatcher func(prevState []tokensystem.TokenView, diff types.TokenSubsystemDiff) ([]tokensystem.TokenView, error)
type TokenPoolSubsystemPatcher func(prevState *poolregistry.TokenPoolsRegistryView, diff types.TokenPoolSubsystemDiff) (*poolregistry.TokenPoolsRegistryView, error)

type UniswapV2SubsystemCopier func(src []uniswapv2.PoolView) []uniswapv2.PoolView
type UniswapV3SubsystemCopier func(src []uniswapv3.PoolView) []uniswapv3.PoolView
type PancakeswapV3SubsystemCopier func(src []uniswapv3.PoolView) []uniswapv3.PoolView
type PoolRegistrySubsystemCopier func(src []poolregistry.PoolView) []poolregistry.PoolView
type TokenSubsystemCopier func(src []tokensystem.TokenView) []tokensystem.TokenView
type TokenPoolSubsystemCopier func(src *poolregistry.TokenPoolsRegistryView) *poolregistry.TokenPoolsRegistryView

// --- Config and Main Struct ---

// DefiStatePatcherConfig holds all the individual patcher and copier functions as dependencies.
type DefiStatePatcherConfig struct {
	Logger                       Logger
	UniswapV2SubsystemPatcher    UniswapV2SubsystemPatcher
	UniswapV3SubsystemPatcher    UniswapV3SubsystemPatcher
	PoolRegistrySubsystemPatcher PoolRegistrySubsystemPatcher
	TokenSubsystemPatcher        TokenSubsystemPatcher
	TokenPoolSubsystemPatcher    TokenPoolSubsystemPatcher
	UniswapV2SubsystemCopier     UniswapV2SubsystemCopier
	UniswapV3SubsystemCopier     UniswapV3SubsystemCopier
	PoolRegistrySubsystemCopier  PoolRegistrySubsystemCopier
	TokenSubsystemCopier         TokenSubsystemCopier
	TokenPoolSubsystemCopier     TokenPoolSubsystemCopier
}

// DefiStatePatcher is the main patcher engine.
type DefiStatePatcher struct {
	logger                       Logger
	uniswapV2SubsystemPatcher    UniswapV2SubsystemPatcher
	uniswapV3SubsystemPatcher    UniswapV3SubsystemPatcher
	poolRegistrySubsystemPatcher PoolRegistrySubsystemPatcher
	tokenSubsystemPatcher        TokenSubsystemPatcher
	tokenPoolSubsystemPatcher    TokenPoolSubsystemPatcher
	uniswapV2SubsystemCopier     UniswapV2SubsystemCopier
	uniswapV3SubsystemCopier     UniswapV3SubsystemCopier
	poolRegistrySubsystemCopier  PoolRegistrySubsystemCopier
	tokenSubsystemCopier         TokenSubsystemCopier
	tokenPoolSubsystemCopier     TokenPoolSubsystemCopier
}

// --- Implementation ---

// validate checks if the configuration is valid.
func (c *DefiStatePatcherConfig) validate() error {
	if c.Logger == nil {
		return errors.New("config: Logger cannot be nil")
	}
	if c.UniswapV2SubsystemPatcher == nil || c.UniswapV2SubsystemCopier == nil {
		return errors.New("config: UniswapV2 patcher and copier cannot be nil")
	}
	if c.UniswapV3SubsystemPatcher == nil || c.UniswapV3SubsystemCopier == nil {
		return errors.New("config: UniswapV3 patcher and copier cannot be nil")
	}

	if c.PoolRegistrySubsystemPatcher == nil || c.PoolRegistrySubsystemCopier == nil {
		return errors.New("config: PoolRegistry patcher and copier cannot be nil")
	}
	if c.TokenSubsystemPatcher == nil || c.TokenSubsystemCopier == nil {
		return errors.New("config: TokenSubsystem patcher and copier cannot be nil")
	}
	if c.TokenPoolSubsystemPatcher == nil || c.TokenPoolSubsystemCopier == nil {
		return errors.New("config: TokenPoolSubsystem patcher and copier cannot be nil")
	}
	return nil
}

// NewDefiStatePatcher constructs a new patcher from a configuration.
func NewDefiStatePatcher(cfg *DefiStatePatcherConfig) (*DefiStatePatcher, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &DefiStatePatcher{
		logger:                       cfg.Logger,
		uniswapV2SubsystemPatcher:    cfg.UniswapV2SubsystemPatcher,
		uniswapV3SubsystemPatcher:    cfg.UniswapV3SubsystemPatcher,
		poolRegistrySubsystemPatcher: cfg.PoolRegistrySubsystemPatcher,
		tokenSubsystemPatcher:        cfg.TokenSubsystemPatcher,
		tokenPoolSubsystemPatcher:    cfg.TokenPoolSubsystemPatcher,
		uniswapV2SubsystemCopier:     cfg.UniswapV2SubsystemCopier,
		uniswapV3SubsystemCopier:     cfg.UniswapV3SubsystemCopier,
		poolRegistrySubsystemCopier:  cfg.PoolRegistrySubsystemCopier,
		tokenSubsystemCopier:         cfg.TokenSubsystemCopier,
		tokenPoolSubsystemCopier:     cfg.TokenPoolSubsystemCopier,
	}, nil
}

// Patch is the main orchestrator method. It creates a new, complete DefiStateEngineView
// by applying a diff to a previous view.
func (p *DefiStatePatcher) Patch(prevView *types.DefiStateEngineView, diff *types.DefiStateEngineDiffView) (*types.DefiStateEngineView, error) {
	// 1. Integrity Check
	if prevView.Block.Number.Uint64() != diff.FromBlock {
		return nil, fmt.Errorf("mismatched fromBlock: prevView is %d, diff expects %d", prevView.Block.Number.Uint64(), diff.FromBlock)
	}

	// 2. Create the new view and DEEP COPY all subsystem data from the previous view.
	newView := &types.DefiStateEngineView{
		ChainID:    prevView.ChainID,
		Timestamp:  diff.Timestamp,
		Block:      diff.ToBlock,
		Subsystems: types.SubsystemView{},
	}

	// Safely copy data for each subsystem, handling nil cases gracefully.
	newView.Subsystems.UniswapV2.Error = prevView.Subsystems.UniswapV2.Error
	if prevView.Subsystems.UniswapV2.Data != nil {
		data := make(map[types.ProtocolName][]uniswapv2.PoolView, len(prevView.Subsystems.UniswapV2.Data))
		for protocol, view := range prevView.Subsystems.UniswapV2.Data {
			data[protocol] = p.uniswapV2SubsystemCopier(view)
		}
		// set uniswapV2 data for newView
		newView.Subsystems.UniswapV2.Data = data
	}

	newView.Subsystems.UniswapV3.Error = prevView.Subsystems.UniswapV3.Error
	if prevView.Subsystems.UniswapV3.Data != nil {
		data := make(map[types.ProtocolName][]uniswapv3.PoolView, len(prevView.Subsystems.UniswapV3.Data))
		for protocol, view := range prevView.Subsystems.UniswapV3.Data {
			data[protocol] = p.uniswapV3SubsystemCopier(view)
		}
		// set uniswapV3 data for newView
		newView.Subsystems.UniswapV3.Data = data
	}

	newView.Subsystems.PoolRegistry.Error = prevView.Subsystems.PoolRegistry.Error
	if prevView.Subsystems.PoolRegistry.Data != nil {
		newView.Subsystems.PoolRegistry.Data = p.poolRegistrySubsystemCopier(prevView.Subsystems.PoolRegistry.Data)
	}

	newView.Subsystems.TokenSystem.Error = prevView.Subsystems.TokenSystem.Error
	if prevView.Subsystems.TokenSystem.Data != nil {
		newView.Subsystems.TokenSystem.Data = p.tokenSubsystemCopier(prevView.Subsystems.TokenSystem.Data)
	}

	newView.Subsystems.TokenPoolSystem.Error = prevView.Subsystems.TokenPoolSystem.Error
	if prevView.Subsystems.TokenPoolSystem.Data != nil {
		newView.Subsystems.TokenPoolSystem.Data = p.tokenPoolSubsystemCopier(prevView.Subsystems.TokenPoolSystem.Data)
	}

	// now that we have created deep copies of view data into newView, we need to update newView with diffs
	// we need to handle each subsystem separately

	// uniswapV2 subsystem diff will have a length if there is a diff to process

	for protocol, protocolDiff := range diff.Subsystems.UniswapV2 {
		if !protocolDiff.IsEmpty() {
			newData, err := p.uniswapV2SubsystemPatcher(newView.Subsystems.UniswapV2.Data[protocol], protocolDiff)
			if err != nil {
				return nil, err
			}

			// update view for subsystem
			newView.Subsystems.UniswapV2.Data[protocol] = newData
		}
	}

	// uniswapV3 subsystem diff will have a length if there is a diff to process

	for protocol, protocolDiff := range diff.Subsystems.UniswapV3 {
		if !protocolDiff.IsEmpty() {
			newData, err := p.uniswapV3SubsystemPatcher(newView.Subsystems.UniswapV3.Data[protocol], protocolDiff)
			if err != nil {
				return nil, err
			}

			// update view for subsystem
			newView.Subsystems.UniswapV3.Data[protocol] = newData
		}
	}

	// ... (The same pattern would apply for Balancer, etc.)

	// --- Handle Low-Level Subsystem Diffs ---
	if !diff.Subsystems.PoolRegistry.IsEmpty() {
		patchedData, err := p.poolRegistrySubsystemPatcher(newView.Subsystems.PoolRegistry.Data, diff.Subsystems.PoolRegistry)
		if err != nil {
			p.logger.Error("Failed to apply PoolRegistry patch", "error", err)
			newView.Subsystems.PoolRegistry.Error = err.Error()
		} else {
			newView.Subsystems.PoolRegistry.Data = patchedData
		}
	}

	if !diff.Subsystems.TokenSystem.IsEmpty() {
		patchedData, err := p.tokenSubsystemPatcher(newView.Subsystems.TokenSystem.Data, diff.Subsystems.TokenSystem)
		if err != nil {
			p.logger.Error("Failed to apply TokenSystem patch", "error", err)
			newView.Subsystems.TokenSystem.Error = err.Error()
		} else {
			newView.Subsystems.TokenSystem.Data = patchedData
		}
	}

	if !diff.Subsystems.TokenPoolSystem.IsEmpty() {
		patchedData, err := p.tokenPoolSubsystemPatcher(newView.Subsystems.TokenPoolSystem.Data, diff.Subsystems.TokenPoolSystem)
		if err != nil {
			p.logger.Error("Failed to apply TokenPoolSystem patch", "error", err)
			newView.Subsystems.TokenPoolSystem.Error = err.Error()
		} else {
			newView.Subsystems.TokenPoolSystem.Data = patchedData
		}
	}

	return newView, nil
}
