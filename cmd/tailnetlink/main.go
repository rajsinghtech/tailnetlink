package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/bridge"
	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/metrics"
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
	if len(args) > 0 && args[0] == "prune" {
		return runPrune(args[1:], stdout)
	}
	fs := flag.NewFlagSet("tailnetlink", flag.ContinueOnError)
	fs.SetOutput(stdout)
	var (
		dataFile        = fs.String("data", "tailnetlink.json", "path to config/state JSON file")
		listenAddr      = fs.String("listen", "", "web UI listen address (default 127.0.0.1:8888)")
		metricsListen   = fs.String("metrics-listen", "", "address for /healthz, /readyz and /metrics (default 127.0.0.1:9090); \"off\" turns it off")
		uiFlag          = fs.Bool("ui", true, "serve the read-only web UI locally and publish it in every tailnet; -ui=false turns both off whatever the config says")
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
	metricsAddr := cfgStore.Get().MetricsAddr
	if *metricsListen != "" {
		metricsAddr = *metricsListen
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
	// The UI is on unless -ui=false or ui.enabled is false at startup. With
	// it on, a later config change can still withdraw or republish the VIP;
	// the local listener follows the setting at startup.
	uiOn := *uiFlag && cfgStore.Get().UIEnabled()
	srv := server.New(addr, stateStore, cfgStore.Get, logger)
	var uiHandler http.Handler
	if *uiFlag {
		uiHandler = srv.Handler()
	}
	mgr := bridge.New(stateStore, logger, uiHandler)
	mgr.SetDefaultStateDir(filepath.Join(filepath.Dir(*dataFile), "tailnetlink-state"))
	mt := metrics.New()
	mgr.SetMetrics(mt)

	// Apply initial config (no-op if empty).
	go mgr.Reconcile(ctx, cfgStore.Get())

	// Hot-reload when the config file changes.
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

	// The UI and metrics listeners report here when they stop. Either one
	// failing (say its port is taken) shuts the process down.
	srvErr := make(chan error, 2)
	running := 0
	if uiOn {
		running++
		go func() { srvErr <- srv.Run(ctx) }()
	} else {
		logger.Info("web UI is off")
	}
	if metricsAddr != "off" && metricsAddr != "" {
		running++
		logger.Info("metrics and health listening", "addr", metricsAddr)
		go func() { srvErr <- metrics.Serve(ctx, metricsAddr, metrics.Handler(mt, mgr.Ready)) }()
	}

	code := 0
	select {
	case <-ctx.Done():
	case err := <-srvErr:
		running--
		logger.Error("server failed", "err", err)
		code = 1
		cancel()
	}

	closeCtx, closeCancel := context.WithTimeout(context.Background(), *shutdownTimeout)
	defer closeCancel()
	if err := mgr.Close(closeCtx); err != nil {
		logger.Error("shutdown did not finish in time", "err", err)
		return 1
	}
	for ; running > 0; running-- {
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

// runPrune deletes every service this instance owns. See bridge.Prune.
func runPrune(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("tailnetlink prune", flag.ContinueOnError)
	fs.SetOutput(stdout)
	dataFile := fs.String("data", "tailnetlink.json", "path to config JSON file")
	dryRun := fs.Bool("dry-run", false, "print what would be deleted without deleting it")
	fs.Usage = func() {
		fmt.Fprintln(stdout, "usage: tailnetlink prune [-data file] [-dry-run]")
		fmt.Fprintln(stdout, "Deletes every VIP service owned by this border name in every configured tailnet,")
		fmt.Fprintln(stdout, "and removes their addresses from split-DNS. Stop tailnetlink first.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	cfg, err := config.Load(*dataFile)
	if err != nil {
		fmt.Fprintln(stdout, "prune:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	actions, err := bridge.Prune(ctx, cfg, *dryRun)
	prefix := ""
	if *dryRun {
		prefix = "would "
	}
	for _, a := range actions {
		fmt.Fprintf(stdout, "%s%s\n", prefix, a)
	}
	if err != nil {
		fmt.Fprintln(stdout, "prune:", err)
		return 1
	}
	if len(actions) == 0 {
		fmt.Fprintln(stdout, "nothing to prune")
	}
	return 0
}
