package tokenpoolsystem

import (
	"testing"

	"github.com/Iwinswap/iwinswap-defi-state-client-go/types/poolregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeepCopy(t *testing.T) {
	t.Run("should handle a nil pointer", func(t *testing.T) {
		var src *poolregistry.TokenPoolsRegistryView = nil
		dst := DeepCopy(src)
		assert.Nil(t, dst, "DeepCopy of a nil pointer should be nil")
	})

	t.Run("should perform a deep copy and ensure immutability", func(t *testing.T) {
		// --- Setup ---
		src := &poolregistry.TokenPoolsRegistryView{
			Tokens:      []uint64{10, 20},
			Pools:       []uint64{100, 200},
			Adjacency:   [][]int{{1, 2}, {3}},
			EdgeTargets: []int{5, 6},
			EdgePools:   [][]int{{101}, {201, 202}},
		}

		// --- Act ---
		dst := DeepCopy(src)

		// --- Assert ---

		// 1. Verify the copy is not the same pointer
		require.NotSame(t, src, dst, "The new view should have a different memory address")

		// 2. Verify the content is initially identical
		assert.Equal(t, src, dst, "The content of the views should be equal after the copy")

		// 3. Mutate the original view to prove the copy is independent
		src.Tokens[0] = 99
		src.Adjacency[0][0] = -1
		src.EdgePools[1] = append(src.EdgePools[1], 999) // Change slice length and capacity

		// 4. Assert that the destination view remains unchanged
		assert.Equal(t, uint64(10), dst.Tokens[0], "dst.Tokens should not be affected by changes to src")
		assert.Equal(t, 1, dst.Adjacency[0][0], "dst.Adjacency should not be affected by changes to src")
		assert.Len(t, dst.EdgePools[1], 2, "dst.EdgePools should not have its length changed")
		assert.Equal(t, []int{201, 202}, dst.EdgePools[1], "dst.EdgePools content should be unchanged")
	})
}
