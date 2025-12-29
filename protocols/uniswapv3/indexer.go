package uniswapv3

// Indexer is a concrete implementation of the defistate.UniswapV3Indexer interface.
type Indexer struct{}

// New creates a new Indexer.
func New() *Indexer {
	return &Indexer{}
}

// Index creates an indexed Uniswap V3 system from a raw slice of pools.
func (i *Indexer) Index(pools []PoolView) *IndexableUniswapV3System {
	return NewIndexableUniswapV3System(pools)
}

// IndexableUniswapV3System provides fast, indexed access to Uniswap V3 pool data.
type IndexableUniswapV3System struct {
	byID map[uint64]PoolView
	all  []PoolView
}

// NewIndexableUniswapV3System creates a new indexed Uniswap V3 system.
func NewIndexableUniswapV3System(pools []PoolView) *IndexableUniswapV3System {
	byID := make(map[uint64]PoolView, len(pools))

	for _, p := range pools {
		byID[p.ID] = p
	}

	return &IndexableUniswapV3System{
		byID: byID,
		all:  pools,
	}
}

// GetByID retrieves a pool by its unique ID.
func (ius *IndexableUniswapV3System) GetByID(id uint64) (PoolView, bool) {
	p, ok := ius.byID[id]
	return p, ok
}

// All returns a defensive copy of the slice of all pools.
func (ius *IndexableUniswapV3System) All() []PoolView {
	allCopy := make([]PoolView, len(ius.all))
	copy(allCopy, ius.all)
	return allCopy
}
