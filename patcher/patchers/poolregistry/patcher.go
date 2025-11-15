package poolregistry

import (
	"github.com/Iwinswap/iwinswap-defi-state-client-go/patcher"
	"github.com/Iwinswap/iwinswap-defi-state-client-go/types"
	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/poolregistry"
)

var _ patcher.PoolRegistrySubsystemPatcher = Patcher

// Patcher is a concrete implementation of the PoolRegistrySubsystemPatcher function type.
// It efficiently constructs a new state for the pool registry by applying a diff to a previous state.
// The logic is optimized for performance using a map for O(1) average time complexity lookups.
func Patcher(prevState []poolregistry.PoolView, diff types.PoolRegistrySubsystemDiff) ([]poolregistry.PoolView, error) {
	// 1. Create a map from the previous state for efficient manipulation.
	// Since poolregistry.PoolView contains no pointer fields, a direct copy is safe.
	newStateMap := make(map[uint64]poolregistry.PoolView, len(prevState))
	for _, pool := range prevState {
		newStateMap[pool.ID] = pool
	}

	// 2. Process deletions.
	for _, poolIDToDelete := range diff.Deletions {
		delete(newStateMap, poolIDToDelete)
	}

	// 3. Process additions.
	for _, addedPool := range diff.Additions {
		newStateMap[addedPool.ID] = addedPool
	}

	// 4. Convert the map back to a slice for the final state.
	finalState := make([]poolregistry.PoolView, 0, len(newStateMap))
	for _, pool := range newStateMap {
		finalState = append(finalState, pool)
	}

	return finalState, nil
}
