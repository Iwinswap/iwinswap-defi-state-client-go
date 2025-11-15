package uniswapv3

import (
	"math/big"
	"testing"

	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/uniswapv3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeepCopyV3(t *testing.T) {
	t.Run("should handle a nil slice", func(t *testing.T) {
		var src []uniswapv3.PoolView = nil
		dst := DeepCopy(src)
		assert.Nil(t, dst, "DeepCopy of a nil slice should be nil")
	})

	t.Run("should handle an empty slice", func(t *testing.T) {
		src := []uniswapv3.PoolView{}
		dst := DeepCopy(src)
		require.NotNil(t, dst, "DeepCopy of an empty slice should not be nil")
		assert.Empty(t, dst, "DeepCopy of an empty slice should be empty")
		assert.NotSame(t, &src, &dst)
	})

	t.Run("should perform a deep copy and ensure immutability", func(t *testing.T) {
		// --- Setup ---
		src := []uniswapv3.PoolView{
			{
				PoolViewMinimal: uniswapv3.PoolViewMinimal{
					ID:           1,
					Liquidity:    big.NewInt(10000),
					SqrtPriceX96: big.NewInt(20000),
				},

				Ticks: []uniswapv3.TickInfo{
					{Index: -10, LiquidityNet: big.NewInt(100), LiquidityGross: big.NewInt(100)},
					{Index: 10, LiquidityNet: big.NewInt(-50), LiquidityGross: big.NewInt(50)},
				},
			},
			{
				PoolViewMinimal: uniswapv3.PoolViewMinimal{
					ID:           2,
					Liquidity:    big.NewInt(30000),
					SqrtPriceX96: big.NewInt(40000),
				},

				Ticks: nil, // Test nil slice handling
			},
		}

		// --- Act ---
		dst := DeepCopy(src)

		// --- Assert ---

		// 1. Verify basic structure and content
		require.NotSame(t, &src, &dst, "The new slice should have a different memory address")
		require.Len(t, dst, len(src))
		assert.Equal(t, src, dst, "The content of the slices should be equal after the copy")

		// 2. Verify deep copy of pool-level pointers
		assert.NotSame(t, src[0].Liquidity, dst[0].Liquidity, "Pointers to Liquidity should be different")

		// 3. Verify deep copy of nested Ticks slice and its elements' pointers
		require.NotNil(t, src[0].Ticks)
		require.NotNil(t, dst[0].Ticks)
		assert.NotSame(t, &src[0].Ticks[0], &dst[0].Ticks[0], "Pointers to TickInfo objects should be different")
		assert.NotSame(t, src[0].Ticks[0].LiquidityNet, dst[0].Ticks[0].LiquidityNet, "Pointers to LiquidityNet within ticks should be different")

		// 4. Mutate the original slice at every level to prove the copy is independent
		src[0].PoolViewMinimal.ID = 99
		src[0].Liquidity.SetInt64(99999)
		src[0].Ticks[0].LiquidityNet.SetInt64(-12345)

		// 5. Assert that the destination slice remains completely unchanged
		assert.Equal(t, uint64(1), dst[0].ID, "dst[0].ID should not be affected by changes to src")
		assert.Equal(t, int64(10000), dst[0].Liquidity.Int64(), "dst[0].Liquidity should not be affected")
		assert.Equal(t, int64(100), dst[0].Ticks[0].LiquidityNet.Int64(), "dst[0].Ticks[0].LiquidityNet should not be affected")
		assert.Nil(t, dst[1].Ticks, "Nil Ticks slice should be preserved")
	})
}
