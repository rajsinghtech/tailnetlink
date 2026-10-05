package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
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
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	os.Exit(run(os.Args[1:], os.Stdout, sig))
}

// forceExit ends the process on a second signal. A variable so tests can
// catch it.
var forceExit = os.Exit

// run is main without the process-global parts. It returns the exit code.
// The first value on sig starts a clean shutdown; a second one exits at once.
func run(args []string, stdout io.Writer, sig <-chan os.Signal) int {
	fs := flag.NewFlagSet("tailnetlink", flag.ContinueOnError)
	fs.SetOutput(stdout)
	var (
		dataFile        = fs.String("data", "tailnetlink.json", "path to config/state JSON file")
		listenAddr      = fs.String("listen", "", "web UI listen address (default :8888)")
		logLevel        = fs.String("log-level", "info", "log level: debug, info, warn, error")
		shutdownTimeout = fs.Duration("shutdown-timeout", 20*time.Second, "how long to wait for a clean shutdown before giving up")
	)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	level := slog.LevelInfo
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	logger := slog.New(slog.NewTextHandler(stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	cfgStore, err := config.NewStore(*dataFile)
	if err != nil {
		logger.Error("failed to load config", "err", err)
		return 1
	}

	addr := cfgStore.Get().ListenAddr
	if *listenAddr != "" {
		addr = *listenAddr
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		s, ok := <-sig
		if !ok {
			return
		}
		logger.Info("shutting down", "signal", fmt.Sprint(s), "timeout", *shutdownTimeout)
		cancel()
		if s, ok := <-sig; ok {
			logger.Warn("second signal, exiting now", "signal", fmt.Sprint(s))
			forceExit(1)
		}
	}()

	stateStore := state.New()
	mgr := bridge.New(stateStore, logger, addr)

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

	srvErr := make(chan error, 1)
	go func() { srvErr <- server.New(addr, stateStore, cfgStore, logger).Run(ctx) }()

	code := 0
	select {
	case <-ctx.Done():
	case err := <-srvErr:
		logger.Error("server failed", "err", err)
		code = 1
		cancel()
		srvErr = nil
	}

	closeCtx, closeCancel := context.WithTimeout(context.Background(), *shutdownTimeout)
	defer closeCancel()
	if err := mgr.Close(closeCtx); err != nil {
		logger.Error("shutdown did not finish in time", "err", err)
		return 1
	}
	if srvErr != nil {
		select {
		case err := <-srvErr:
			if err != nil {
				logger.Error("server failed", "err", err)
				code = 1
			}
		case <-closeCtx.Done():
			logger.Error("web server did not stop in time")
			return 1
		}
	}
	logger.Info("stopped")
	return code
}
