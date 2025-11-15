package uniswapv2

import (
	"math/big"

	"github.com/Iwinswap/iwinswap-defi-state-client-go/patcher"

	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/uniswapv2"
)

var _ patcher.UniswapV2SubsystemCopier = DeepCopy

// deepCopyPool creates a new PoolView with its own memory for pointer types like *big.Int.
// This is essential to prevent the new state from sharing memory with the old state.
func deepCopyPool(p uniswapv2.PoolView) uniswapv2.PoolView {
	// Create a new copy of the struct. This copies all value types (ID, Address, etc.).
	newPool := p

	// For pointer types, we must create new objects and copy the values.
	// If we don't, both the old and new PoolView would point to the same big.Int object in memory.
	if p.Reserve0 != nil {
		newPool.Reserve0 = new(big.Int).Set(p.Reserve0)
	}
	if p.Reserve1 != nil {
		newPool.Reserve1 = new(big.Int).Set(p.Reserve1)
	}
	return newPool
}

// DeepCopy is a concrete implementation of the CopyUniswapV2Subsystem function type.
// It creates a completely independent copy of a slice of PoolView objects,
// ensuring that the new state does not share any memory with the previous state.
func DeepCopy(src []uniswapv2.PoolView) []uniswapv2.PoolView {
	if src == nil {
		return nil
	}

	// Pre-allocate a new slice with the same length and capacity as the source
	// for better performance.
	dst := make([]uniswapv2.PoolView, len(src))

	// Iterate over the source slice and perform a deep copy of each element.
	for i, pool := range src {
		dst[i] = deepCopyPool(pool)
	}

	return dst
}
