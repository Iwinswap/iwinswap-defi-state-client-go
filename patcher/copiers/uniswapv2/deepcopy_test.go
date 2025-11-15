package uniswapv2

import (
	"math/big"
	"testing"

	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/uniswapv2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeepCopy(t *testing.T) {
	t.Run("should handle a nil slice", func(t *testing.T) {
		var src []uniswapv2.PoolView = nil
		dst := DeepCopy(src)
		assert.Nil(t, dst, "DeepCopy of a nil slice should be nil")
	})

	t.Run("should handle an empty slice", func(t *testing.T) {
		src := []uniswapv2.PoolView{}
		dst := DeepCopy(src)
		require.NotNil(t, dst, "DeepCopy of an empty slice should not be nil")
		assert.Empty(t, dst, "DeepCopy of an empty slice should be empty")
		// Check that it's a new slice instance, not the same one
		assert.NotSame(t, &src, &dst)
	})

	t.Run("should perform a deep copy and ensure immutability", func(t *testing.T) {
		// --- Setup ---
		src := []uniswapv2.PoolView{
			{
				ID:       1,
				Reserve0: big.NewInt(1000),
				Reserve1: big.NewInt(2000),
			},
			{
				ID:       2,
				Reserve0: big.NewInt(3000),
				Reserve1: big.NewInt(4000),
			},
			{
				// Pool with a nil reserve to test nil pointer handling
				ID:       3,
				Reserve0: nil,
				Reserve1: big.NewInt(5000),
			},
		}

		// --- Act ---
		dst := DeepCopy(src)

		// --- Assert ---

		// 1. Verify the copy is not the same slice instance
		require.NotSame(t, &src, &dst, "The new slice should have a different memory address")
		require.Len(t, dst, len(src), "The new slice should have the same length")

		// 2. Verify the content is initially identical
		assert.Equal(t, src, dst, "The content of the slices should be equal after the copy")

		// 3. Verify that the pointers to big.Int are different (the core of the deep copy)
		require.NotNil(t, src[0].Reserve0)
		require.NotNil(t, dst[0].Reserve0)
		assert.NotSame(t, src[0].Reserve0, dst[0].Reserve0, "Pointers to Reserve0 in the first element should be different")
		assert.NotSame(t, src[1].Reserve1, dst[1].Reserve1, "Pointers to Reserve1 in the second element should be different")
		assert.Nil(t, dst[2].Reserve0, "Nil pointers should be preserved as nil")

		// 4. Mutate the original slice to prove the copy is independent
		src[0].Reserve0.SetInt64(9999)
		src[0].ID = 100

		// 5. Assert that the destination slice remains unchanged
		assert.Equal(t, int64(1000), dst[0].Reserve0.Int64(), "dst[0].Reserve0 should not be affected by changes to src")
		assert.Equal(t, uint64(1), dst[0].ID, "dst[0].ID should not be affected by changes to src")
		assert.NotEqual(t, src[0].Reserve0, dst[0].Reserve0, "The Reserve0 values should now be different")
	})
}
