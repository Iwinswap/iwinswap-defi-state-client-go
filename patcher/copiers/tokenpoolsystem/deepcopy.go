package tokenpoolsystem

import (
	"github.com/Iwinswap/iwinswap-defi-state-client-go/patcher"

	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/poolregistry"
)

var _ patcher.TokenPoolSubsystemCopier = DeepCopy

// DeepCopy is a concrete implementation of the CopyTokenPoolSubsystem function type.
// It creates a new TokenPoolsRegistryView with its own memory for all its slices.
// This is essential to prevent the new state from sharing memory with the old state.
func DeepCopy(src *poolregistry.TokenPoolsRegistryView) *poolregistry.TokenPoolsRegistryView {
	if src == nil {
		return nil
	}

	dst := &poolregistry.TokenPoolsRegistryView{}

	// Create new slices and copy the data.
	// This creates a new backing array for each slice.
	if src.Tokens != nil {
		dst.Tokens = make([]uint64, len(src.Tokens))
		copy(dst.Tokens, src.Tokens)
	}

	if src.Pools != nil {
		dst.Pools = make([]uint64, len(src.Pools))
		copy(dst.Pools, src.Pools)
	}

	if src.EdgeTargets != nil {
		dst.EdgeTargets = make([]int, len(src.EdgeTargets))
		copy(dst.EdgeTargets, src.EdgeTargets)
	}

	// For slices of slices, we must iterate and copy each inner slice.
	if src.Adjacency != nil {
		dst.Adjacency = make([][]int, len(src.Adjacency))
		for i, inner := range src.Adjacency {
			if inner != nil {
				dst.Adjacency[i] = make([]int, len(inner))
				copy(dst.Adjacency[i], inner)
			}
		}
	}

	if src.EdgePools != nil {
		dst.EdgePools = make([][]int, len(src.EdgePools))
		for i, inner := range src.EdgePools {
			if inner != nil {
				dst.EdgePools[i] = make([]int, len(inner))
				copy(dst.EdgePools[i], inner)
			}
		}
	}

	return dst
}
