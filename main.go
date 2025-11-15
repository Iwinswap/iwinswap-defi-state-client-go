package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	jsonrpcclient "github.com/Iwinswap/iwinswap-defi-state-client-go/jsonrpc"
	patcher "github.com/Iwinswap/iwinswap-defi-state-client-go/patcher"
	poolregistrydefistatecopier "github.com/Iwinswap/iwinswap-defi-state-client-go/patcher/copiers/poolregistry"
	tokenpoolsystemdefistatecopier "github.com/Iwinswap/iwinswap-defi-state-client-go/patcher/copiers/tokenpoolsystem"
	tokensystemdefistatecopier "github.com/Iwinswap/iwinswap-defi-state-client-go/patcher/copiers/tokensystem"
	uniswapv2defistatecopier "github.com/Iwinswap/iwinswap-defi-state-client-go/patcher/copiers/uniswapv2"
	uniswapv3defistatecopier "github.com/Iwinswap/iwinswap-defi-state-client-go/patcher/copiers/uniswapv3"
	poolregistrydefistatepatcher "github.com/Iwinswap/iwinswap-defi-state-client-go/patcher/patchers/poolregistry"
	tokenpoolsystemdefistatepatcher "github.com/Iwinswap/iwinswap-defi-state-client-go/patcher/patchers/tokenpoolsystem"
	tokensystemdefistatepatcher "github.com/Iwinswap/iwinswap-defi-state-client-go/patcher/patchers/tokensystem"
	uniswapv2defistatepatcher "github.com/Iwinswap/iwinswap-defi-state-client-go/patcher/patchers/uniswapv2"
	uniswapv3defistatepatcher "github.com/Iwinswap/iwinswap-defi-state-client-go/patcher/patchers/uniswapv3"
)

func main() {
	// --- flags / config ---
	stateEngineURL := flag.String("state-engine-url", "", "URL of the state engine JSON-RPC endpoint")
	flag.Parse()

	if *stateEngineURL == "" {
		flag.Usage()
		os.Exit(1)
	}

	// --- context & logging ---
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logHandler := slog.NewJSONHandler(os.Stdout, nil)
	logger := slog.New(logHandler)

	// --- patcher setup ---
	patcherConfig := &patcher.DefiStatePatcherConfig{
		UniswapV2SubsystemPatcher:    uniswapv2defistatepatcher.Patcher,
		UniswapV3SubsystemPatcher:    uniswapv3defistatepatcher.Patcher,
		PoolRegistrySubsystemPatcher: poolregistrydefistatepatcher.Patcher,
		TokenSubsystemPatcher:        tokensystemdefistatepatcher.Patcher,
		TokenPoolSubsystemPatcher:    tokenpoolsystemdefistatepatcher.Patcher,
		UniswapV2SubsystemCopier:     uniswapv2defistatecopier.DeepCopy,
		UniswapV3SubsystemCopier:     uniswapv3defistatecopier.DeepCopy,
		PoolRegistrySubsystemCopier:  poolregistrydefistatecopier.DeepCopy,
		TokenSubsystemCopier:         tokensystemdefistatecopier.DeepCopy,
		TokenPoolSubsystemCopier:     tokenpoolsystemdefistatecopier.DeepCopy,
		Logger:                       logger.With("component", "defi-state-patcher"),
	}

	defistatePatcher, err := patcher.NewDefiStatePatcher(patcherConfig)
	if err != nil {
		logger.Error("failed to create defi state patcher", "err", err)
		os.Exit(1)
	}

	// --- JSON-RPC client ---
	defiStateClientConfig := jsonrpcclient.Config{
		URL:          *stateEngineURL,
		Logger:       logger.With("component", "defi-state-client"),
		BufferSize:   10,
		StatePatcher: defistatePatcher.Patch,
	}

	client, err := jsonrpcclient.NewClient(ctx, defiStateClientConfig)
	if err != nil {
		logger.Error("failed to create defi state client", "err", err)
		os.Exit(1)
	}

	// --- signal handling / graceful shutdown ---
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	select {
	case sig := <-sigChan:
		logger.Info("received signal, shutting down", "signal", sig.String())
	case <-client.View():
		// drain the view channel
	}

}
