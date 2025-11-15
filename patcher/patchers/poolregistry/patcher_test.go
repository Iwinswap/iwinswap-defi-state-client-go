package poolregistry

import (
	"testing"

	"github.com/Iwinswap/iwinswap-defi-state-client-go/types"
	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/poolregistry"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to find a pool by ID in a slice, for testing assertions.
func findPoolByID(pools []poolregistry.PoolView, id uint64) *poolregistry.PoolView {
	for i := range pools {
		if pools[i].ID == id {
			return &pools[i]
		}
	}
	return nil
}

func TestPatcher(t *testing.T) {
	// --- Base Data for Tests ---
	pool1Old := poolregistry.PoolView{ID: 1, Address: common.HexToAddress("0x1")}
	pool2Old := poolregistry.PoolView{ID: 2, Address: common.HexToAddress("0x2")}
	pool3Old := poolregistry.PoolView{ID: 3, Address: common.HexToAddress("0x3")}

	initialState := []poolregistry.PoolView{pool1Old, pool2Old, pool3Old}

	t.Run("should handle only additions", func(t *testing.T) {
		pool4New := poolregistry.PoolView{ID: 4, Address: common.HexToAddress("0x4")}
		diff := types.PoolRegistrySubsystemDiff{
			Additions: []poolregistry.PoolView{pool4New},
		}

		newState, err := Patcher(initialState, diff)
		require.NoError(t, err)

		assert.Len(t, newState, 4, "Should have 4 pools after addition")
		newPool := findPoolByID(newState, 4)
		require.NotNil(t, newPool)
		assert.Equal(t, common.HexToAddress("0x4"), newPool.Address)
	})

	t.Run("should handle only deletions", func(t *testing.T) {
		diff := types.PoolRegistrySubsystemDiff{
			Deletions: []uint64{2}, // Delete pool with ID 2
		}

		newState, err := Patcher(initialState, diff)
		require.NoError(t, err)

		assert.Len(t, newState, 2, "Should have 2 pools after deletion")
		deletedPool := findPoolByID(newState, 2)
		assert.Nil(t, deletedPool, "Pool 2 should be deleted")
	})

	t.Run("should handle a mix of additions and deletions", func(t *testing.T) {
		// Add pool 4, delete pool 3
		pool4New := poolregistry.PoolView{ID: 4, Address: common.HexToAddress("0x4")}
		diff := types.PoolRegistrySubsystemDiff{
			Additions: []poolregistry.PoolView{pool4New},
			Deletions: []uint64{3},
		}

		newState, err := Patcher(initialState, diff)
		require.NoError(t, err)

		assert.Len(t, newState, 3, "Final state should have 3 pools")
		// Verify addition
		assert.NotNil(t, findPoolByID(newState, 4))
		// Verify deletion
		assert.Nil(t, findPoolByID(newState, 3))
		// Verify unchanged pools are still present
		assert.NotNil(t, findPoolByID(newState, 1))
		assert.NotNil(t, findPoolByID(newState, 2))
	})

	t.Run("should handle an empty diff", func(t *testing.T) {
		diff := types.PoolRegistrySubsystemDiff{}

		newState, err := Patcher(initialState, diff)
		require.NoError(t, err)

		// Using assert.ElementsMatch is a robust way to compare slices regardless of order.
		assert.ElementsMatch(t, initialState, newState, "State should be unchanged for an empty diff")
	})

	t.Run("should be correct when starting from an empty state", func(t *testing.T) {
		emptyState := []poolregistry.PoolView{}
		pool1New := poolregistry.PoolView{ID: 1, Address: common.HexToAddress("0x1")}
		diff := types.PoolRegistrySubsystemDiff{
			Additions: []poolregistry.PoolView{pool1New},
		}

		newState, err := Patcher(emptyState, diff)
		require.NoError(t, err)
		assert.Len(t, newState, 1)
		assert.Equal(t, uint64(1), newState[0].ID)
	})
}
