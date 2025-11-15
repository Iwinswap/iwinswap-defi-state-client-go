package tokensystem

import (
	"github.com/Iwinswap/iwinswap-defi-state-client-go/patcher"

	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/tokensystem"
)

var _ patcher.TokenSubsystemCopier = DeepCopy

// DeepCopy is a concrete implementation of the CopyTokenSubsystem function type.
// It creates a completely independent copy of a slice of TokenView objects.
// Since tokensystem.TokenView contains only value types (no pointers),
// a standard copy of the slice elements is sufficient to ensure immutability.
func DeepCopy(src []tokensystem.TokenView) []tokensystem.TokenView {
	if src == nil {
		return nil
	}

	dst := make([]tokensystem.TokenView, len(src))
	copy(dst, src)

	return dst
}
