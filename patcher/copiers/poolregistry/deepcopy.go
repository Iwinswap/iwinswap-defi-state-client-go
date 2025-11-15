package poolregistry

import (
	"github.com/Iwinswap/iwinswap-defi-state-client-go/patcher"
	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/poolregistry"
)

var _ patcher.PoolRegistrySubsystemCopier = DeepCopy

// DeepCopy is a concrete implementation of the CopyPoolRegistrySubsystem function type.
// It creates a completely independent copy of a slice of PoolView objects.
// Since poolregistry.PoolView contains only value types (no pointers), a standard
// copy of the slice elements is sufficient to ensure the new state is immutable.
func DeepCopy(src []poolregistry.PoolView) []poolregistry.PoolView {
	if src == nil {
		return nil
	}

	// Create a new slice and copy the elements. Go's default struct copy
	// is by value, which is safe here.
	dst := make([]poolregistry.PoolView, len(src))
	copy(dst, src)

	return dst
}
