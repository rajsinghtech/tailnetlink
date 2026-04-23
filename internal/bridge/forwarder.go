package bridge

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/state"
	"tailscale.com/tsnet"
)

// Forwarder registers the destination tsnet node as a VIP service host and
// forwards each accepted connection through the source tsnet to the actual
// backend device.
//
// Traffic path:
//
//	raj-client → VIP IP:port
//	  → Tailscale routes to this tsnet node (via ListenService)
//	  → forwarder dials source device IP:port through srcSrv
//	  → bidirectional copy
type Forwarder struct {
	listenSrv   *tsnet.Server // destination tailnet — registered as VIP service host
	dialSrv     *tsnet.Server // source tailnet — dials actual backend
	vip         *VIPService
	bridgeID    string // store key: ruleName/fqdn
	timeout     time.Duration
	store       *state.Store
	logger      *slog.Logger
	connCounter atomic.Int64

	cancel    context.CancelFunc
	listeners []net.Listener
	wg        sync.WaitGroup
}

func NewForwarder(
	listenSrv *tsnet.Server,
	dialSrv *tsnet.Server,
	vip *VIPService,
	bridgeID string,
	timeout time.Duration,
	store *state.Store,
	logger *slog.Logger,
) *Forwarder {
	return &Forwarder{
		listenSrv: listenSrv,
		dialSrv:   dialSrv,
		vip:       vip,
		bridgeID:  bridgeID,
		timeout:   timeout,
		store:     store,
		logger:    logger,
	}
}

func (f *Forwarder) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	f.cancel = cancel

	for _, port := range f.vip.Ports {
		// PROXYProtocolVersion:1 prepends "PROXY TCP4 <real-src> ..." so we can WhoIs the actual peer.
		ln, err := listenServiceWithRetry(f.listenSrv, f.vip.ServiceName, tsnet.ServiceModeTCP{
			Port:                 uint16(port),
			PROXYProtocolVersion: 1,
		})
		if err != nil {
			cancel()
			for _, existing := range f.listeners {
				existing.Close()
			}
			f.wg.Wait()
			return fmt.Errorf("listen service %s port %d: %w", f.vip.ServiceName, port, err)
		}
		f.listeners = append(f.listeners, ln)
		f.logger.Info("forwarder: service host registered", "service", f.vip.ServiceName, "port", port)

		f.wg.Add(1)
		go f.accept(ctx, ln, port)
	}
	return nil
}

func (f *Forwarder) Stop() {
	if f.cancel != nil {
		f.cancel()
	}
	for _, ln := range f.listeners {
		_ = ln.Close()
	}
	f.wg.Wait()
}

func (f *Forwarder) accept(ctx context.Context, ln net.Listener, port int) {
	defer f.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				f.logger.Warn("forwarder: accept error", "err", err)
				return
			}
		}
		go f.handle(ctx, conn, port)
	}
}

func (f *Forwarder) handle(ctx context.Context, client net.Conn, port int) {
	defer client.Close()

	target := net.JoinHostPort(f.vip.SourceIP.String(), strconv.Itoa(port))

	dialCtx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	// Dial through the source tailnet to reach the actual backend service.
	upstream, err := f.dialSrv.Dial(dialCtx, "tcp", target)
	if err != nil {
		f.logger.Warn("forwarder: dial failed", "target", target, "err", err)
		if ctx.Err() == nil {
			f.store.Log("warn", fmt.Sprintf("dial failed: %s → %s: %v", f.vip.ServiceName, target, err), nil)
		}
		return
	}
	defer upstream.Close()

	client, realAddr, err := readProxyHeader(client)
	if err != nil {
		f.logger.Warn("forwarder: PROXY header read failed", "err", err)
		return
	}

	nodeName, identity := whoIsIdentity(ctx, f.listenSrv, realAddr)

	clientAddr := realAddr
	if clientAddr == "" {
		clientAddr = client.RemoteAddr().String()
	}
	connID := fmt.Sprintf("%s#%d", f.vip.ServiceName, f.connCounter.Add(1))
	f.store.OpenConn(state.ConnEntry{
		ID:          connID,
		BridgeID:    f.bridgeID,
		ServiceName: f.vip.ServiceName,
		ClientAddr:  clientAddr,
		NodeName:    nodeName,
		Identity:    identity,
		TargetAddr:  target,
		OpenedAt:    time.Now(),
	})
	f.store.IncrBridgeConn(f.bridgeID, 1)
	f.store.Log("info", fmt.Sprintf("conn: %s ← %s", f.vip.ServiceName, connLabel(clientAddr, nodeName, identity)), nil)

	var bytesIn, bytesOut atomic.Int64
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := io.Copy(upstream, client)
		bytesIn.Add(n)
		if hc, ok := upstream.(halfCloser); ok {
			_ = hc.CloseWrite()
		} else {
			_ = upstream.Close()
		}
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(client, upstream)
		bytesOut.Add(n)
		if hc, ok := client.(halfCloser); ok {
			_ = hc.CloseWrite()
		} else {
			_ = client.Close()
		}
	}()

	wg.Wait()

	in, out := bytesIn.Load(), bytesOut.Load()
	f.store.CloseConn(connID, in, out)
	f.store.AddBridgeBytes(f.bridgeID, in, out)
	f.store.IncrBridgeConn(f.bridgeID, -1)
	f.store.Log("info", fmt.Sprintf("conn closed: %s — %s in, %s out", f.vip.ServiceName, formatBytes(in), formatBytes(out)), nil)
}

// whoIsIdentity resolves the Tailscale node name and identity (login or tag) for addr.
func whoIsIdentity(ctx context.Context, srv *tsnet.Server, addr string) (nodeName, identity string) {
	if addr == "" {
		return
	}
	lc, err := srv.LocalClient()
	if err != nil {
		return
	}
	who, err := lc.WhoIs(ctx, addr)
	if err != nil || who.Node == nil {
		return
	}
	nodeName = strings.SplitN(who.Node.Name, ".", 2)[0]
	if who.UserProfile != nil && who.UserProfile.LoginName != "" {
		identity = who.UserProfile.LoginName
	} else if len(who.Node.Tags) > 0 {
		identity = who.Node.Tags[0]
	}
	return
}

// bufferedConn wraps a net.Conn so that bytes already consumed into a
// bufio.Reader are not lost when subsequent Read calls are made.
type bufferedConn struct {
	r *bufio.Reader
	net.Conn
}

func (bc *bufferedConn) Read(b []byte) (int, error) { return bc.r.Read(b) }

// readProxyHeader reads the PROXY protocol v1 line from conn and returns:
//   - a wrapped conn whose Read delivers the remaining (payload) bytes
//   - the real client address "IP:port" extracted from the header
//   - any error
//
// "PROXY UNKNOWN" connections (local) return an empty realAddr.
func readProxyHeader(conn net.Conn) (net.Conn, string, error) {
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return conn, "", fmt.Errorf("read PROXY header: %w", err)
	}
	wrapped := &bufferedConn{r: br, Conn: conn}
	parts := strings.Fields(strings.TrimRight(line, "\r\n"))
	if len(parts) < 2 || parts[0] != "PROXY" {
		return wrapped, "", fmt.Errorf("invalid PROXY header: %q", line)
	}
	if parts[1] == "UNKNOWN" {
		return wrapped, "", nil
	}
	if len(parts) < 6 {
		return wrapped, "", fmt.Errorf("truncated PROXY header: %q", line)
	}
	// parts: PROXY TCP4/TCP6 <src-ip> <dst-ip> <src-port> <dst-port>
	realAddr := net.JoinHostPort(parts[2], parts[4])
	return wrapped, realAddr, nil
}
