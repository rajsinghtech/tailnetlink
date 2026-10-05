package metrics

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Handler serves /healthz (the process is up), /readyz (ready returns nil)
// and /metrics. Nothing else, and it is never mounted on the UI.
func Handler(m *Metrics, ready func() error) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if ready != nil {
			if err := ready(); err != nil {
				http.Error(w, "not ready: "+err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		io.WriteString(w, "ok\n")
	})
	if m != nil {
		mux.Handle("GET /metrics", promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{}))
	}
	return mux
}

// Serve listens on addr and serves h until ctx is done. It returns once the
// listener is closed; a failure to listen is returned at once.
func Serve(ctx context.Context, addr string, h http.Handler) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("metrics listen: %w", err)
	}
	return ServeListener(ctx, ln, h)
}

// ServeListener is Serve on an existing listener.
func ServeListener(ctx context.Context, ln net.Listener, h http.Handler) error {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
