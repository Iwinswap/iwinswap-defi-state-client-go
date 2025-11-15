package poolregistry

import (
	"testing"

	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/poolregistry"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeepCopy(t *testing.T) {
	t.Run("should handle a nil slice", func(t *testing.T) {
		var src []poolregistry.PoolView = nil
		dst := DeepCopy(src)
		assert.Nil(t, dst, "DeepCopy of a nil slice should be nil")
	})

	t.Run("should handle an empty slice", func(t *testing.T) {
		src := []poolregistry.PoolView{}
		dst := DeepCopy(src)
		require.NotNil(t, dst, "DeepCopy of an empty slice should not be nil")
		assert.Empty(t, dst, "DeepCopy of an empty slice should be empty")
		assert.NotSame(t, &src, &dst)
	})

	t.Run("should perform a deep copy and ensure immutability", func(t *testing.T) {
		// --- Setup ---
		addr1 := common.HexToAddress("0x0000000000000000000000000000000000000001")
		addr2 := common.HexToAddress("0x0000000000000000000000000000000000000002")

		src := []poolregistry.PoolView{
			{ID: 1, Address: addr1, Type: 1},
			{ID: 2, Address: addr2, Type: 2},
		}

		// --- Act ---
		dst := DeepCopy(src)

		// --- Assert ---

		// 1. Verify the copy is not the same slice instance
		require.NotSame(t, &src, &dst, "The new slice should have a different memory address")
		require.Len(t, dst, len(src), "The new slice should have the same length")

		// 2. Verify the content is initially identical
		assert.Equal(t, src, dst, "The content of the slices should be equal after the copy")

		// 3. Mutate the original slice to prove the copy is independent
		src[0].ID = 99
		src[0].Address = common.HexToAddress("0xffffffffffffffffffffffffffffffffffffffff")

		// 4. Assert that the destination slice remains unchanged
		assert.Equal(t, uint64(1), dst[0].ID, "dst[0].ID should not be affected by changes to src")
		assert.Equal(t, addr1, dst[0].Address, "dst[0].Address should not be affected by changes to src")
		assert.NotEqual(t, src[0].Address, dst[0].Address, "The Address values should now be different")
	})
}
