package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/defistate/defi-state-client-go/cmd/client/config"
	"github.com/defistate/defi-state-client-go/differ"
	"github.com/defistate/defi-state-client-go/engine"
	"github.com/defistate/defi-state-client-go/pkg/chains"
	ethpkg "github.com/defistate/defi-state-client-go/pkg/chains/ethereum"
	"github.com/defistate/defi-state-client-go/protocols/poolregistry"
	"github.com/defistate/defi-state-client-go/protocols/token"
	"github.com/defistate/defi-state-client-go/protocols/uniswapv2"
	"github.com/defistate/defi-state-client-go/protocols/uniswapv3"
	"github.com/defistate/defi-state-client-go/streams/jsonrpc/client"
	"github.com/prometheus/client_golang/prometheus"
)

// --- VISUAL CONSTANTS ---
const (
	Reset  = "\033[0m"
	Bold   = "\033[1m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
	Gray   = "\033[37m"

	DefaultClientStateBufferSize = 100
)

// header prints a styled section header
func header(title string) {
	fmt.Println("\n" + Bold + Cyan + ":: " + title + " ::" + Reset)
}

// SafeState is a thread-safe container for the latest engine state.
type SafeState struct {
	mu    sync.RWMutex
	state *engine.State
}

func (s *SafeState) Update(newState *engine.State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = newState
}

func (s *SafeState) Get() *engine.State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

type ChainStateOps interface {
	Diff(old *engine.State, new *engine.State) (*differ.StateDiff, error)
	Patch(oldState *engine.State, diff *differ.StateDiff) (*engine.State, error)
	DecodeStateJSON(schema engine.ProtocolSchema, data json.RawMessage) (any, error)
	DecodeStateDiffJSON(schema engine.ProtocolSchema, data json.RawMessage) (any, error)
}

func main() {
	// --- 1. SETUP LOGGING (To File) ---
	logFile, err := os.OpenFile("client.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		panic(fmt.Sprintf("Failed to open log file: %v", err))
	}
	defer logFile.Close()

	rootLogHandler := slog.NewJSONHandler(logFile, nil)
	rootLogger := slog.New(rootLogHandler)

	closeApp := func() {
		fmt.Println("\n" + Red + "Fatal error occurred. Check client.log for details." + Reset)
		os.Exit(1)
	}

	// --- 2. CONFIG & CONTEXT ---
	prometheusRegistry := prometheus.DefaultRegisterer
	cfg, err := loadConfig()
	if err != nil {
		rootLogger.Error("Failed to load configuration", "error", err)
		closeApp()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --- 3. INITIALIZE OPS ---
	var chainStateOps ChainStateOps

	switch cfg.ChainID.Uint64() {
	case chains.Mainnet:
		chainStateOps, err = ethpkg.NewStateOps(rootLogger, prometheusRegistry)
		if err != nil {
			rootLogger.Error("Failed to initialize Chain State Ops", "chain_id", cfg.ChainID, "error", err)
			closeApp()
		}
	default:
		rootLogger.Error(fmt.Sprintf("Chain State Ops not found for chain with ID %d", cfg.ChainID.Uint64()))
		closeApp()
	}

	// --- 4. INITIALIZE CLIENT ---
	client, err := client.NewClient(
		ctx,
		client.Config{
			URL:              cfg.StateStreamURL,
			Logger:           rootLogger.With("component", "jsonrpc-client"),
			BufferSize:       DefaultClientStateBufferSize,
			StatePatcher:     chainStateOps.Patch,
			StateDecoder:     chainStateOps.DecodeStateJSON,
			StateDiffDecoder: chainStateOps.DecodeStateDiffJSON,
		},
	)

	if err != nil {
		rootLogger.Error("Failed to initialize Client", "chain_id", cfg.ChainID, "error", err)
		closeApp()
	}

	// --- 5. START CONSOLE & STATE LOOP ---
	safeState := &SafeState{}

	fmt.Println(Green + "Starting DeFi State Client..." + Reset)
	fmt.Println("Logs are being written to 'client.log'")
	go runConsole(ctx, safeState)

	for {
		select {
		case n := <-client.State():
			safeState.Update(n)

		case err := <-client.Err():
			rootLogger.Error("Fatal client error", "error", err)
			closeApp()

		case <-ctx.Done():
			fmt.Println("\n" + Yellow + "Shutting down..." + Reset)
			return
		}
	}
}

// runConsole handles user input and display.
func runConsole(ctx context.Context, safeState *SafeState) {
	reader := bufio.NewReader(os.Stdin)
	time.Sleep(500 * time.Millisecond)

	for {
		if ctx.Err() != nil {
			return
		}

		printMenu()

		fmt.Print(Bold + "Enter selection: " + Reset)
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading input:", err)
			continue
		}
		input = strings.TrimSpace(input)

		handleCommand(input, safeState, reader)

		fmt.Println("\n" + Gray + "[Press Enter to continue]" + Reset)
		reader.ReadString('\n')
	}
}

func printMenu() {
	fmt.Print("\033[H\033[2J") // Clear screen
	fmt.Println(Bold + "DEFI STATE CLIENT" + Reset + Gray + " | v0.1.0" + Reset)
	fmt.Println(Gray + "-----------------------------------" + Reset)
	fmt.Printf(" %s1.%s Current Block Info\n", Cyan, Reset)
	fmt.Printf(" %s2.%s Protocol Summary\n", Cyan, Reset)
	fmt.Printf(" %s3.%s Find Pool  %s(by Address/Key)%s\n", Cyan, Reset, Gray, Reset)
	fmt.Printf(" %s4.%s Find Pools %s(by Token Address)%s\n", Cyan, Reset, Gray, Reset)
	fmt.Printf(" %s5.%s Watch Pool %s(Live Monitor)%s\n", Cyan, Reset, Gray, Reset)
	fmt.Println(Gray + "-----------------------------------" + Reset)
	fmt.Printf(" %sh.%s Help / Architecture\n", Yellow, Reset)
	fmt.Printf(" %sq.%s Quit\n", Red, Reset)
	fmt.Println("")
}

func handleCommand(input string, safeState *SafeState, reader *bufio.Reader) {
	state := safeState.Get()

	// Allow help and quit even if state isn't ready
	if state == nil && input != "q" && input != "h" {
		fmt.Println("\n" + Yellow + "[INFO] Waiting for first state update... (Check connection/logs)" + Reset)
		return
	}

	switch input {
	case "1":
		printBlockInfo(state)
	case "2":
		printProtocolSummary(state)
	case "3":
		findPool(state, reader)
	case "4":
		findPoolsByToken(state, reader)
	case "5":
		watchPool(safeState, reader)
	case "h":
		printHelp()
	case "q":
		exitConsole()
	default:
		fmt.Println(Red + "Unknown command." + Reset)
	}
}

// --- COMMAND HANDLERS ---

func printHelp() {
	// Clear screen to make reading the architecture easy
	fmt.Print("\033[H\033[2J")

	header("DEFI STATE STREAM ARCHITECTURE")
	fmt.Println(Bold + "Concept: Aggregated State" + Reset)
	fmt.Println("The DeFi State Stream is a normalized, real-time aggregation of multiple DeFi protocols.")
	fmt.Println("It abstracts the complexity of raw blockchain storage into a clean, typed Go structure.")
	fmt.Println("")

	fmt.Println(Bold + "1. THE DATA STRUCTURE" + Reset)
	fmt.Println("   The root object is " + Cyan + "State" + Reset + ", which contains:")
	fmt.Println("   - " + Yellow + "Block" + Reset + ": Essential context (Number, Timestamp, Gas).")
	fmt.Println("   - " + Yellow + "Protocols" + Reset + ": A map of Protocol IDs to their specific state.")
	fmt.Println("")
	fmt.Println("   Inside each Protocol State:")
	fmt.Println("   - " + Yellow + "Schema" + Reset + ": The decode contract (e.g., 'defistate/uniswap-v2-system@v1').")
	fmt.Println("   - " + Yellow + "Data" + Reset + ":   Already typed Go objects. You use the Schema to assert")
	fmt.Println("             the correct type (e.g., casting `any` to `UniswapV3Pool`).")
	fmt.Println("")

	fmt.Println(Bold + "2. THE THREE PRIMITIVES" + Reset)
	fmt.Println("   These internal protocols provide the backbone of the entire stream:")
	fmt.Println("")
	fmt.Printf("   A. %sPool Registry%s\n", Cyan, Reset)
	fmt.Println("      - Assigns a unique " + Green + "uint64 ID" + Reset + " to every protocol's pool.")
	fmt.Println("      - Maps this ID to a " + Green + "32-byte Key" + Reset + " (holding the Address or Identifier).")
	fmt.Println("")
	fmt.Printf("   B. %sToken Registry%s\n", Cyan, Reset)
	fmt.Println("      - Assigns a unique " + Green + "uint64 ID" + Reset + " to every ERC20 token.")
	fmt.Println("      - Provides static metadata (Symbol, Decimals, Name).")
	fmt.Println("")
	fmt.Printf("   C. %sToken-Pool Graph%s\n", Cyan, Reset)
	fmt.Println("      - A traversable graph using the primitive uint64 IDs.")
	fmt.Println("      - Answers: 'What pools hold this token?' or 'How do I route WETH -> USDC?'")
	fmt.Println("      - Provides the barebones for sophisticated routing algorithms.")
	fmt.Println("")

	fmt.Println(Bold + "3. DEFI PROTOCOLS" + Reset)
	fmt.Println("   (e.g., Uniswap V2, V3, Curve)")
	fmt.Println("   These protocols provide high-frequency market data (Reserves, Ticks, Liquidity).")
	fmt.Println("   They are indexed from the blockchain and guaranteed in-sync with the Block.")
	fmt.Println("")

	fmt.Println(Gray + "---------------------------------------------------------------" + Reset)
	fmt.Println(Bold + "PURPOSE OF THIS CONSOLE" + Reset)
	fmt.Println("This tool is designed to help you understand and utilize the stream.")
	fmt.Println("Run the available commands to explore the graph relationships.")
	fmt.Println(Green + "Goal: " + Reset + "Use these functions as examples to build your own")
	fmt.Println("sophisticated arbitrage or routing algorithms on top of the stream.")
	fmt.Println(Gray + "---------------------------------------------------------------" + Reset)
}

func printBlockInfo(state *engine.State) {
	ts := time.Unix(0, int64(state.Timestamp)).Format("15:04:05")

	fmt.Printf("\n%sSTATUS  ::%s Block %s#%d%s | Chain %s%d%s | Time %s%s%s\n",
		Green, Reset,
		Bold, state.Block.Number, Reset,
		Bold, state.ChainID, Reset,
		Bold, ts, Reset,
	)
}

func printProtocolSummary(state *engine.State) {
	header("PROTOCOL SUMMARY")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
	fmt.Fprintln(w, "PROTOCOL ID\tSCHEMA\tSTATUS\t")
	fmt.Fprintln(w, "-----------\t------\t------\t")

	errCount := 0
	for id, p := range state.Protocols {
		status := Green + "OK" + Reset
		if p.Error != "" {
			status = Red + "ERROR" + Reset
			errCount++
		}

		// Truncate long IDs for display
		pID := string(id)
		if len(pID) > 25 {
			pID = pID[:22] + "..."
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t\n", pID, p.Schema, status)
	}
	w.Flush()

	fmt.Printf("\n%sProtocols with Errors: %d%s\n", Bold, errCount, Reset)
}

func findPool(state *engine.State, reader *bufio.Reader) {
	fmt.Print("\n" + Bold + "[Find Pool] Enter Pool Address or Key (32-byte hex): " + Reset)
	key := readAndParseKey(reader)
	if key == nil {
		return
	}

	printPoolByKey(state, *key)
}

func findPoolsByToken(state *engine.State, reader *bufio.Reader) {
	fmt.Print("\n" + Bold + "[Find Pools] Enter Token Address (Hex): " + Reset)
	input, _ := reader.ReadString('\n')
	input = strings.TrimPrefix(strings.TrimSpace(input), "0x")
	if input == "" {
		return
	}

	// 1. Parse Input
	var searchAddrBytes []byte

	var err error
	searchAddrBytes, err = hex.DecodeString(input)
	if err != nil {
		fmt.Printf(Red+"[ERROR] Invalid hex format: %v%s\n", err, Reset)
		return
	}

	// 2. Resolve Address -> TokenID (Token Registry)
	tokenProto, ok := state.Protocols[engine.ProtocolID("token-system")]
	if !ok {
		fmt.Println(Red + "[ERROR] 'token-system' missing." + Reset)
		return
	}
	tokens, ok := tokenProto.Data.([]token.TokenView)
	if !ok {
		fmt.Printf(Red+"[ERROR] Bad Token Data Type: %T%s\n", tokenProto.Data, Reset)
		return
	}

	var tokenID uint64
	var tokenSymbol string
	foundToken := false

	// Linear scan (Optimization: build a map in production)
	for _, t := range tokens {
		if bytes.Equal(t.Address[:], searchAddrBytes) {
			tokenID = t.ID
			tokenSymbol = t.Symbol
			foundToken = true
			break
		}
	}

	if !foundToken {
		fmt.Println(Red + "[NOT FOUND] Token address not found in registry." + Reset)
		return
	}
	fmt.Printf("%sFound Token: %s (ID: %d)%s\n", Green, tokenSymbol, tokenID, Reset)

	// 3. Query Graph: TokenID -> []PoolID
	graphProto, ok := state.Protocols[engine.ProtocolID("token-pool-graph-system")]
	if !ok {
		fmt.Println(Red + "[ERROR] 'token-pool-graph-system' missing." + Reset)
		return
	}

	graphView, ok := graphProto.Data.(*poolregistry.TokenPoolsRegistryView)
	if !ok {
		if val, ok := graphProto.Data.(poolregistry.TokenPoolsRegistryView); ok {
			graphView = &val
		} else {
			fmt.Printf(Red+"[ERROR] Bad Graph Data Type: %T%s\n", graphProto.Data, Reset)
			return
		}
	}

	// Find token index in graph
	tokenIndex := -1
	for i, id := range graphView.Tokens {
		if id == tokenID {
			tokenIndex = i
			break
		}
	}

	if tokenIndex == -1 {
		fmt.Println(Yellow + "[INFO] Token has no pools in the graph." + Reset)
		return
	}

	// Traverse Adjacency
	uniquePools := make(map[uint64]struct{})
	if tokenIndex < len(graphView.Adjacency) {
		edgeIndices := graphView.Adjacency[tokenIndex]
		for _, edgeIndex := range edgeIndices {
			if edgeIndex < len(graphView.EdgePools) {
				poolIndices := graphView.EdgePools[edgeIndex]
				for _, poolIndex := range poolIndices {
					if poolIndex < len(graphView.Pools) {
						pID := graphView.Pools[poolIndex]
						uniquePools[pID] = struct{}{}
					}
				}
			}
		}
	}

	if len(uniquePools) == 0 {
		fmt.Println(Yellow + "[INFO] No active pools found for this token." + Reset)
		return
	}

	fmt.Printf("Found %d active pools for %s. Resolving details...\n", len(uniquePools), tokenSymbol)

	// 4. Resolve PoolID -> Details (Pool Registry)
	poolProto, ok := state.Protocols[engine.ProtocolID("pool-system")]
	if !ok {
		return
	}
	poolReg, ok := poolProto.Data.(poolregistry.PoolRegistryView)
	if !ok {
		return
	}

	// Build lookup map
	registryMap := make(map[uint64]poolregistry.PoolView)
	for _, p := range poolReg.Pools {
		registryMap[p.ID] = p
	}

	// 5. Print Results (Improved with Tabwriter)
	header(fmt.Sprintf("POOLS FOR %s", tokenSymbol))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
	fmt.Fprintln(w, "ID\tPROTOCOL\tPOOL ADDRESS\t")
	fmt.Fprintln(w, "--\t--------\t------------\t")

	for pID := range uniquePools {
		pool, exists := registryMap[pID]

		idStr := fmt.Sprintf("%d", pID)
		protoName := fmt.Sprintf("%s???%s", Red, Reset)
		addrStr := "<Missing>"

		if exists {
			if name, ok := poolReg.Protocols[pool.Protocol]; ok {
				protoName = string(name)
				if len(protoName) > 25 {
					protoName = protoName[:22] + "..."
				}
			}
			addr, _ := pool.Key.ToAddress()
			addrStr = fmt.Sprintf("0x%x", addr)
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t\n", idStr, protoName, addrStr)
	}

	w.Flush()
}

func watchPool(safeState *SafeState, reader *bufio.Reader) {
	fmt.Print("\n" + Bold + "[Watch Pool] Enter Pool Address or Key (32-byte hex): " + Reset)
	key := readAndParseKey(reader)
	if key == nil {
		return
	}

	fmt.Println(Green + "Starting Live Watch... (Press 'Enter' to stop)" + Reset)
	time.Sleep(1 * time.Second)

	stopCh := make(chan struct{})
	go func() {
		reader.ReadString('\n')
		close(stopCh)
	}()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	lastBlock := new(big.Int)

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			state := safeState.Get()
			if state == nil || state.Block.Number == nil {
				continue
			}

			if state.Block.Number.Cmp(lastBlock) > 0 {
				lastBlock.Set(state.Block.Number)

				fmt.Print("\033[H\033[2J")
				fmt.Printf(Bold+"--- LIVE MONITOR (Block: %s) ---\n"+Reset, state.Block.Number.String())
				fmt.Println(Gray + "Press ENTER to return to menu." + Reset)

				printPoolByKey(state, *key)
			}
		}
	}
}

// --- HELPERS ---

func readAndParseKey(reader *bufio.Reader) *[32]byte {
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}

	var searchKey [32]byte
	var inputBytes []byte
	var err error

	if strings.HasPrefix(input, "0x") {
		inputBytes, err = hex.DecodeString(input[2:])
		if err != nil {
			fmt.Printf(Red+"[ERROR] Invalid hex format: %v%s\n", err, Reset)
			return nil
		}
	} else {
		inputBytes = []byte(input)
	}

	if len(inputBytes) > 32 {
		fmt.Printf(Red+"[ERROR] Key too long (%d bytes). Max 32 bytes.%s\n", len(inputBytes), Reset)
		return nil
	}

	copy(searchKey[32-len(inputBytes):], inputBytes)
	fmt.Printf(Gray+"Searching for Key: 0x%x...%s\n", searchKey, Reset)
	return &searchKey
}

func printPoolByKey(state *engine.State, searchKey [32]byte) {
	protocolState, ok := state.Protocols[engine.ProtocolID("pool-system")]
	if !ok {
		fmt.Println(Red + "[ERROR] Protocol 'pool-system' not found." + Reset)
		return
	}

	registry, ok := protocolState.Data.(poolregistry.PoolRegistryView)
	if !ok {
		return
	}

	var foundPool *poolregistry.PoolView
	for _, pool := range registry.Pools {
		if pool.Key == searchKey {
			foundPool = &pool
			break
		}
	}

	if foundPool != nil {
		header("POOL REGISTRY DATA")
		fmt.Printf("Registry ID:     %d\n", foundPool.ID)
		fmt.Printf("Pool Key:        0x%x\n", hex.EncodeToString(foundPool.Key[:]))

		if protocolID, exists := registry.Protocols[foundPool.Protocol]; exists {
			fmt.Printf("Protocol:        %s%s%s (ID: %d)\n", Cyan, protocolID, Reset, foundPool.Protocol)
			inspectProtocolData(state, protocolID, foundPool.ID)
		} else {
			fmt.Printf("Protocol:        %sUnknown%s (ID: %d)\n", Red, Reset, foundPool.Protocol)
		}
	} else {
		fmt.Println(Red + "[NOT FOUND] Pool key not found in registry." + Reset)
	}
}

func inspectProtocolData(state *engine.State, pID engine.ProtocolID, poolID uint64) {
	pState, ok := state.Protocols[pID]
	if !ok {
		fmt.Printf(Yellow+"[WARN] Protocol state for '%s' is not loaded or empty.%s\n", pID, Reset)
		return
	}

	// Helper for aligned printing
	printField := func(key string, value any) {
		fmt.Printf("  %s%-15s%s %v\n", Gray, key+":", Reset, value)
	}

	switch pState.Schema {
	case uniswapv2.UniswapV2ProtocolSchema:
		pools := uniswapv2.NewIndexableUniswapV2System(pState.Data.([]uniswapv2.PoolView))
		pool, found := pools.GetByID(poolID)
		if found {
			header("UNISWAP V2 LIVE DATA")
			printField("Reserve0", pool.Reserve0)
			printField("Reserve1", pool.Reserve1)
		} else {
			fmt.Printf(Yellow+"[WARN] Pool ID %d missing from V2 state.%s\n", poolID, Reset)
		}

	case uniswapv3.UniswapV3ProtocolSchema:
		pools := uniswapv3.NewIndexableUniswapV3System(pState.Data.([]uniswapv3.PoolView))
		pool, found := pools.GetByID(poolID)
		if found {
			header("UNISWAP V3 LIVE DATA")
			printField("Liquidity", pool.Liquidity)
			printField("SqrtPriceX96", pool.SqrtPriceX96)
			printField("Current Tick", fmt.Sprintf("%s%d%s", Yellow, pool.Tick, Reset))
			printField("Active Ticks", len(pool.Ticks))
		} else {
			fmt.Printf(Yellow+"[WARN] Pool ID %d missing from V3 state.%s\n", poolID, Reset)
		}

	default:
		fmt.Printf(Gray+"[INFO] No inspector implemented for schema type: %s%s\n", pState.Schema, Reset)
	}
}

func exitConsole() {
	fmt.Println(Yellow + "Exiting..." + Reset)
	os.Exit(0)
}

func loadConfig() (*config.ClientConfig, error) {
	configPath := flag.String("config", "config.yaml", "Path to the configuration file.")
	flag.Parse()
	log.Printf("Loading configuration from: %s", *configPath)
	return config.LoadConfig(*configPath)
}
