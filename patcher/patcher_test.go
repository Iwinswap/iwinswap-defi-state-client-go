package patcher

import (
	"errors"
	"math/big"
	"testing"

	"github.com/Iwinswap/iwinswap-defi-state-client-go/types"
	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/poolregistry"
	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/tokensystem"
	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/uniswapv2"
	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/uniswapv3"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mocks and Helpers ---

type noOpLogger struct{}

func (l *noOpLogger) Debug(msg string, args ...any) {}
func (l *noOpLogger) Info(msg string, args ...any)  {}
func (l *noOpLogger) Warn(msg string, args ...any)  {}
func (l *noOpLogger) Error(msg string, args ...any) {}

// --- Mock Patcher Implementations ---

func mockUniswapV2Patcher(prevState []uniswapv2.PoolView, diff types.UniswapV2SubsystemDiff) ([]uniswapv2.PoolView, error) {
	return []uniswapv2.PoolView{{ID: 9001}}, nil
}

func mockUniswapV3Patcher(prevState []uniswapv3.PoolView, diff types.UniswapV3SubsystemDiff) ([]uniswapv3.PoolView, error) {
	return []uniswapv3.PoolView{{PoolViewMinimal: uniswapv3.PoolViewMinimal{ID: 9002}}}, nil
}

func mockPoolRegistryPatcher(prevState []poolregistry.PoolView, diff types.PoolRegistrySubsystemDiff) ([]poolregistry.PoolView, error) {
	return []poolregistry.PoolView{{ID: 9004}}, nil
}

func mockTokenSystemPatcher(prevState []tokensystem.TokenView, diff types.TokenSubsystemDiff) ([]tokensystem.TokenView, error) {
	return []tokensystem.TokenView{{ID: 9005}}, nil
}

func mockTokenPoolPatcher(prevState *poolregistry.TokenPoolsRegistryView, diff types.TokenPoolSubsystemDiff) (*poolregistry.TokenPoolsRegistryView, error) {
	return diff.Data, nil
}

func mockFailingUniswapV2Patcher(prevState []uniswapv2.PoolView, diff types.UniswapV2SubsystemDiff) ([]uniswapv2.PoolView, error) {
	return nil, errors.New("mock v2 patcher failed")
}

// --- CORRECTED Mock Copier Implementations ---

func mockUniswapV2Copier(src []uniswapv2.PoolView) []uniswapv2.PoolView {
	dst := make([]uniswapv2.PoolView, len(src))
	copy(dst, src)
	return dst
}

func mockUniswapV3Copier(src []uniswapv3.PoolView) []uniswapv3.PoolView {
	dst := make([]uniswapv3.PoolView, len(src))
	copy(dst, src)
	return dst
}

func mockPoolRegistryCopier(src []poolregistry.PoolView) []poolregistry.PoolView {
	dst := make([]poolregistry.PoolView, len(src))
	copy(dst, src)
	return dst
}

func mockTokenSystemCopier(src []tokensystem.TokenView) []tokensystem.TokenView {
	dst := make([]tokensystem.TokenView, len(src))
	copy(dst, src)
	return dst
}

func mockTokenPoolCopier(src *poolregistry.TokenPoolsRegistryView) *poolregistry.TokenPoolsRegistryView {
	if src == nil {
		return nil
	}
	dst := *src
	return &dst
}

// --- Main Test Suite ---

func TestDefiStatePatcher_Patch(t *testing.T) {
	// --- Base Data for All Tests (Updated for new map structures) ---
	const v2ProtocolName types.ProtocolName = "uniswap_v2_mainnet"
	const v3ProtocolName types.ProtocolName = "uniswap_v3_mainnet"
	const pancakeProtocolName types.ProtocolName = "pancakeswap_v3_bsc"

	prevView := &types.DefiStateEngineView{
		Block: types.BlockSummary{Number: big.NewInt(99)},
		Subsystems: types.SubsystemView{
			UniswapV2: types.UniswapV2SubsystemsResult{
				Data: map[types.ProtocolName][]uniswapv2.PoolView{
					v2ProtocolName: {{ID: 1}},
				},
			},
			UniswapV3: types.UniswapV3SubsystemsResult{
				Data: map[types.ProtocolName][]uniswapv3.PoolView{
					v3ProtocolName: {{PoolViewMinimal: uniswapv3.PoolViewMinimal{ID: 2}}},
				},
			},
		},
	}

	diff := &types.DefiStateEngineDiffView{
		FromBlock: 99,
		ToBlock:   types.BlockSummary{Number: big.NewInt(100)},
		Subsystems: types.SubsystemDiffView{
			UniswapV2: map[types.ProtocolName]types.UniswapV2SubsystemDiff{
				v2ProtocolName: {Additions: []uniswapv2.PoolView{{ID: 10}}},
			},
			UniswapV3: map[types.ProtocolName]types.UniswapV3SubsystemDiff{
				v3ProtocolName: {Updates: []uniswapv3.PoolView{{PoolViewMinimal: uniswapv3.PoolViewMinimal{ID: 20}}}},
			},
		},
	}

	// --- Standard Config for Happy Path Tests ---
	happyPathCfg := &DefiStatePatcherConfig{
		Logger:                       &noOpLogger{},
		UniswapV2SubsystemPatcher:    mockUniswapV2Patcher,
		UniswapV3SubsystemPatcher:    mockUniswapV3Patcher,
		PoolRegistrySubsystemPatcher: mockPoolRegistryPatcher,
		TokenSubsystemPatcher:        mockTokenSystemPatcher,
		TokenPoolSubsystemPatcher:    mockTokenPoolPatcher,
		UniswapV2SubsystemCopier:     mockUniswapV2Copier,
		UniswapV3SubsystemCopier:     mockUniswapV3Copier,
		PoolRegistrySubsystemCopier:  mockPoolRegistryCopier,
		TokenSubsystemCopier:         mockTokenSystemCopier,
		TokenPoolSubsystemCopier:     mockTokenPoolCopier,
	}

	t.Run("should correctly patch all subsystems in a diff", func(t *testing.T) {
		patcher, err := NewDefiStatePatcher(happyPathCfg)
		require.NoError(t, err)

		newView, err := patcher.Patch(prevView, diff)
		require.NoError(t, err)
		require.NotNil(t, newView)

		// Verify top-level fields are updated
		assert.Equal(t, uint64(100), newView.Block.Number.Uint64())

		// Verify that the correct mock patcher was called for each subsystem
		assert.Equal(t, uint64(9001), newView.Subsystems.UniswapV2.Data[v2ProtocolName][0].ID)
		assert.Equal(t, uint64(9002), newView.Subsystems.UniswapV3.Data[v3ProtocolName][0].ID)
	})

	t.Run("should catch and return subpatcher errors", func(t *testing.T) {
		errorCfg := *happyPathCfg
		errorCfg.UniswapV2SubsystemPatcher = mockFailingUniswapV2Patcher
		patcher, err := NewDefiStatePatcher(&errorCfg)
		require.NoError(t, err)

		_, err = patcher.Patch(prevView, diff)
		require.Error(t, err)

	})

	t.Run("should return an error on mismatched FromBlock", func(t *testing.T) {
		patcher, err := NewDefiStatePatcher(happyPathCfg)
		require.NoError(t, err)

		mismatchedDiff := &types.DefiStateEngineDiffView{
			FromBlock: 98,
			ToBlock:   types.BlockSummary{Number: big.NewInt(100)},
		}

		_, err = patcher.Patch(prevView, mismatchedDiff)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mismatched fromBlock")
	})
}
