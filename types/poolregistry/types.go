package poolregistry

import "github.com/ethereum/go-ethereum/common"

// --- Block-Unaware Subsystem Interfaces ---
type PoolView struct {
	ID      uint64         `json:"id"`
	Address common.Address `json:"address"`
	Type    uint8          `json:"type"`
}

// TokenPoolsRegistryView provides a complete, thread-safe snapshot of the graph's
// core data structures. This is optimized for consumers who need to perform
// their own graph traversal or analysis algorithms.
type TokenPoolsRegistryView struct {
	Tokens      []uint64 `json:"tokens"`
	Pools       []uint64 `json:"pools"`
	Adjacency   [][]int  `json:"adjacency"`
	EdgeTargets []int    `json:"edgeTargets"`
	EdgePools   [][]int  `json:"edgePools"`
}
