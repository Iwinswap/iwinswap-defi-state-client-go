package uniswapv3

import (
	"math/big"

	"github.com/Iwinswap/iwinswap-defi-state-client-go/patcher"

	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/uniswapv3"
)

var _ patcher.UniswapV3SubsystemCopier = DeepCopy

// copyTickInfo creates a deep copy of a TickInfo struct, ensuring *big.Int pointers are new instances.
// This is critical for preventing shared memory between state views.
func copyTickInfo(t uniswapv3.TickInfo) uniswapv3.TickInfo {
	newTick := t
	if t.LiquidityNet != nil {
		newTick.LiquidityNet = new(big.Int).Set(t.LiquidityNet)
	}
	if t.LiquidityGross != nil {
		newTick.LiquidityGross = new(big.Int).Set(t.LiquidityGross)
	}
	return newTick
}

// deepCopyPool creates a new PoolView with its own memory for all pointer types,
// including the nested Ticks slice. This is essential for memory safety and state immutability.
func deepCopyPool(p uniswapv3.PoolView) uniswapv3.PoolView {
	newPool := p

	// Deep copy the *big.Int fields.
	if p.Liquidity != nil {
		newPool.Liquidity = new(big.Int).Set(p.Liquidity)
	}
	if p.SqrtPriceX96 != nil {
		newPool.SqrtPriceX96 = new(big.Int).Set(p.SqrtPriceX96)
	}

	// Deep copy the Ticks slice by creating a new slice and then deep-copying each element.
	// If we only copied the slice without copying its elements, the ticks themselves would be shared.
	if p.Ticks != nil {
		newTicks := make([]uniswapv3.TickInfo, len(p.Ticks))
		for i, tick := range p.Ticks {
			newTicks[i] = copyTickInfo(tick)
		}
		newPool.Ticks = newTicks
	}

	return newPool
}

// DeepCopy is a concrete implementation of the CopyUniswapV3Subsystem function type.
// It creates a completely independent copy of a slice of PoolView objects.
func DeepCopy(src []uniswapv3.PoolView) []uniswapv3.PoolView {
	if src == nil {
		return nil
	}

	dst := make([]uniswapv3.PoolView, len(src))
	for i, pool := range src {
		dst[i] = deepCopyPool(pool)
	}

	return dst
}
