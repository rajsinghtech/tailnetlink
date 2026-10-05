package server

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/state"
)

//go:embed web
var webFS embed.FS

// Server serves the read-only web UI and its API. It has no write routes:
// the config file is the only way to change anything.
type Server struct {
	store  *state.Store
	config func() *config.Config
	logger *slog.Logger
	addr   string
}

// New returns a server for addr. config returns the running config; only
// its public view (no oauth blocks) is ever served.
func New(addr string, store *state.Store, config func() *config.Config, logger *slog.Logger) *Server {
	return &Server{addr: addr, store: store, config: config, logger: logger}
}

// Run listens on the configured address and serves until ctx is done.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Serve serves on ln until ctx is done, then shuts down. Open requests,
// including SSE streams, see their context cancelled and get up to
// shutdownGrace to finish.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	s.logger.Info("web UI available", "addr", "http://"+ln.Addr().String())

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		_ = srv.Close()
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// shutdownGrace is how long Serve waits for open requests after ctx is done.
var shutdownGrace = 5 * time.Second

// Handler returns the HTTP handler for the UI and its API. Only GET and
// HEAD are allowed; every other method gets 405.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	webRoot, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err) // the embedded tree always has web/
	}
	mux.Handle("/", http.FileServer(http.FS(webRoot)))
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/bridges", s.handleBridges)
	mux.HandleFunc("/api/connections", s.handleConns)
	mux.HandleFunc("/api/logs", s.handleLogs)
	mux.HandleFunc("/api/events", s.handleSSE)
	return readOnly(mux)
}

// readOnly rejects every method but GET and HEAD.
func readOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "read-only", http.StatusMethodNotAllowed)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// ── Status / data handlers ────────────────────────────────────────────────────

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.store.GetStatus())
}

func (s *Server) handleBridges(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.store.GetBridges())
}

func (s *Server) handleConns(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.store.GetConns())
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.store.GetLogs(100))
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	type initPayload struct {
		Status      state.StatusSnapshot `json:"status"`
		Bridges     []*state.BridgeEntry `json:"bridges"`
		Connections []*state.ConnEntry   `json:"connections"`
		Logs        []state.LogEntry     `json:"logs"`
		Config      json.RawMessage      `json:"config"`
	}
	init := initPayload{
		Status:      s.store.GetStatus(),
		Bridges:     s.store.GetBridges(),
		Connections: s.store.GetConns(),
		Logs:        s.store.GetLogs(50),
		Config:      s.config().PublicJSON(),
	}
	writeSSEEvent(w, state.EventInit, init)
	flusher.Flush()

	ch := s.store.Subscribe()
	defer s.store.Unsubscribe(ch)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprint(w, ": heartbeat\n\n")
			flusher.Flush()
		case event, ok := <-ch:
			if !ok {
				return
			}
			writeSSEEvent(w, event.Type, event.Payload)
			flusher.Flush()
		}
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeSSEEvent(w http.ResponseWriter, eventType string, payload any) {
	data, _ := json.Marshal(payload)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, data)
}
