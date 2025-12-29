package poolregistry

import "github.com/defistate/defi-state-client-go/engine"

// PoolView represents the data for a single pool.
type PoolView struct {
	ID       uint64  `json:"id"`
	Key      PoolKey `json:"key"`      // Renamed from Identifier
	Protocol uint16  `json:"protocol"` // Internal uint16 representation
}

// PoolRegistryView represents the complete state of the registry.
type PoolRegistryView struct {
	Pools     []PoolView                   `json:"pools"`
	Protocols map[uint16]engine.ProtocolID `json:"protocols"`
}
