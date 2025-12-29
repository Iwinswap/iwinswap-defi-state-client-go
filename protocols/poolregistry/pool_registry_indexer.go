package poolregistry

import (
	"github.com/ethereum/go-ethereum/common"
)

type Indexer struct{}

// New creates a new Indexer.
func New() *Indexer {
	return &Indexer{}
}

// Index creates an indexed pool registry from a raw slice of pools.
func (i *Indexer) Index(pools []PoolView) *IndexablePoolRegistry {
	return NewIndexablePoolRegistry(pools)
}

// IndexablePoolRegistry provides fast, indexed access to pool registry data.
type IndexablePoolRegistry struct {
	byID  map[uint64]PoolView
	byKey map[PoolKey]PoolView
	all   []PoolView
}

// NewIndexablePoolRegistry creates a new indexed pool registry from a raw slice.
func NewIndexablePoolRegistry(pools []PoolView) *IndexablePoolRegistry {
	byID := make(map[uint64]PoolView, len(pools))
	byKey := make(map[PoolKey]PoolView, len(pools))

	for _, p := range pools {
		byID[p.ID] = p
		byKey[p.Key] = p
	}

	return &IndexablePoolRegistry{
		byID:  byID,
		byKey: byKey,
		all:   pools,
	}
}

// GetByID retrieves a pool by its unique ID.
func (ipr *IndexablePoolRegistry) GetByID(id uint64) (PoolView, bool) {
	p, ok := ipr.byID[id]
	return p, ok
}

// GetByAddress retrieves a pool by its contract address.
func (ipr *IndexablePoolRegistry) GetByAddress(address common.Address) (PoolView, bool) {
	p, ok := ipr.byKey[AddressToPoolKey(address)]
	return p, ok
}

// GetByPoolKey retrieves a pool by its PoolKey.
func (ipr *IndexablePoolRegistry) GetByPoolKey(key PoolKey) (PoolView, bool) {
	p, ok := ipr.byKey[key]
	return p, ok
}

// All returns a defensive copy of the slice of all pools in the system.
func (ipr *IndexablePoolRegistry) All() []PoolView {
	allCopy := make([]PoolView, len(ipr.all))
	copy(allCopy, ipr.all)
	return allCopy
}
