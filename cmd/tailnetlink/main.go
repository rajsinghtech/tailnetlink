package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/bridge"
	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/server"
	"github.com/rajsinghtech/tailnetlink/internal/state"
)

func main() {
	var (
		dataFile   = flag.String("data", "tailnetlink.json", "path to config/state JSON file")
		listenAddr = flag.String("listen", "", "web UI listen address (default :8888)")
		logLevel   = flag.String("log-level", "info", "log level: debug, info, warn, error")
	)
	flag.Parse()

	level := slog.LevelInfo
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	cfgStore, err := config.NewStore(*dataFile)
	if err != nil {
		logger.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	addr := cfgStore.Get().ListenAddr
	if *listenAddr != "" {
		addr = *listenAddr
	}

	stateStore := state.New()
	mgr := bridge.New(stateStore, logger, addr)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Apply initial config (no-op if empty).
	go mgr.Reconcile(ctx, cfgStore.Get())

	// Hot-reload on every UI-driven change or direct file edit.
	cfgStore.OnChange(func(cfg *config.Config) {
		mgr.Reconcile(ctx, cfg)
	})
	go cfgStore.Watch(ctx, logger)

	// Periodic re-reconcile so rules that exited early (e.g. tailnet not yet
	// connected) are automatically restarted without requiring a config change.
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				mgr.Reconcile(ctx, cfgStore.Get())
			}
		}
	}()

	srv := server.New(addr, stateStore, cfgStore, logger)
	if err := srv.Run(); err != nil {
		logger.Error("server failed", "err", err)
		os.Exit(1)
	}
}
