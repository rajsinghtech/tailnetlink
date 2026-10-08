package bridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rajsinghtech/tailnetlink/internal/config"
	"github.com/rajsinghtech/tailnetlink/internal/state"
	"tailscale.com/tsnet"
)

func TestLocalForwarderDialsTheBackendForEachPort(t *testing.T) {
	old := whoIs
	t.Cleanup(func() { whoIs = old })
	whoIs = func(context.Context, *tsnet.Server, string) (whoIsResult, error) {
		return whoIsResult{}, nil
	}

	backend := func(t *testing.T) (string, <-chan string) {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		got := make(chan string, 1)
		go func() {
			_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
			c, err := ln.Accept()
			if err != nil {
				got <- "accept: " + err.Error()
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			buf, _ := io.ReadAll(c)
			got <- string(buf)
		}()
		return ln.Addr().String(), got
	}
	addr80, body80 := backend(t)
	addr443, body443 := backend(t)

	f := &Forwarder{
		listenSrv: &tsnet.Server{},
		localTargets: map[int]string{
			80:  addr80,
			443: addr443,
		},
		vip:      &VIPService{ServiceName: "svc:app", Ports: []int{80, 443}},
		bridgeID: "app/local/dest/10.0.0.1/app",
		timeout:  time.Second,
		store:    state.New(),
		logger:   discardLogger(),
		rule:     "app",
	}

	dial := func(port int, payload string) {
		t.Helper()
		client, server := net.Pipe()
		go func() {
			_, _ = io.WriteString(server, fmt.Sprintf("PROXY TCP4 100.64.0.1 100.100.0.1 51234 %d\r\n%s", port, payload))
			_ = server.Close()
		}()
		f.handle(context.Background(), client, port)
	}
	dial(80, "from-80")
	dial(443, "from-443")

	if got := <-body80; got != "from-80" {
		t.Errorf("port 80 backend got %q", got)
	}
	if got := <-body443; got != "from-443" {
		t.Errorf("port 443 backend got %q", got)
	}

	// A listen port with no mapping must not dial either backend.
	client, server := net.Pipe()
	go func() {
		_, _ = io.WriteString(server, "PROXY TCP4 100.64.0.1 100.100.0.1 51234 22\r\nnope")
		_ = server.Close()
	}()
	f.handle(context.Background(), client, 22)
	found := false
	for _, l := range f.store.GetLogs(10) {
		if strings.Contains(l.Message, "no local backend for port 22") {
			found = true
		}
	}
	if !found {
		t.Fatal("missing port mapping was not reported")
	}
}

func TestForwarderStartStopTouchesEveryPort(t *testing.T) {
	var mu sync.Mutex
	var opened []net.Listener
	orig := openServiceListener
	t.Cleanup(func() { openServiceListener = orig })
	openServiceListener = func(srv *tsnet.Server, name string, mode tsnet.ServiceMode) (net.Listener, error) {
		tcp, ok := mode.(tsnet.ServiceModeTCP)
		if !ok || name != "svc:app" {
			t.Errorf("listen %s mode %T", name, mode)
		}
		if tcp.Port != 80 && tcp.Port != 443 {
			t.Errorf("listen port %d", tcp.Port)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		mu.Lock()
		opened = append(opened, ln)
		mu.Unlock()
		return ln, nil
	}

	f := &Forwarder{
		listenSrv: &tsnet.Server{},
		vip:       &VIPService{ServiceName: "svc:app", Ports: []int{80, 443}},
		timeout:   time.Second,
		store:     state.New(),
		logger:    discardLogger(),
	}
	if err := f.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(opened) != 2 || len(f.listeners) != 2 {
		t.Fatalf("opened %d listeners, forwarder has %d", len(opened), len(f.listeners))
	}
	f.Stop()
	for _, ln := range opened {
		if c, err := net.DialTimeout("tcp", ln.Addr().String(), 200*time.Millisecond); err == nil {
			c.Close()
			t.Errorf("listener %s still accepting after stop", ln.Addr())
		}
	}
}

func TestForwarderStartFailureClosesEarlierPorts(t *testing.T) {
	var first net.Listener
	orig := openServiceListener
	t.Cleanup(func() { openServiceListener = orig })
	openServiceListener = func(srv *tsnet.Server, name string, mode tsnet.ServiceMode) (net.Listener, error) {
		tcp := mode.(tsnet.ServiceModeTCP)
		if tcp.Port == 443 {
			return nil, errors.New("second port failed")
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		first = ln
		return ln, nil
	}
	f := &Forwarder{
		listenSrv: &tsnet.Server{},
		vip:       &VIPService{ServiceName: "svc:app", Ports: []int{80, 443}},
		timeout:   time.Second,
		store:     state.New(),
		logger:    discardLogger(),
	}
	err := f.Start(context.Background())
	if err == nil || first == nil {
		t.Fatalf("Start err = %v, first listener %v", err, first)
	}
	if c, err := net.DialTimeout("tcp", first.Addr().String(), 200*time.Millisecond); err == nil {
		c.Close()
		t.Error("first listener still open after the second port failed")
	}
}

func TestLocalPortSetHotReload(t *testing.T) {
	tm := newTestManager(t)
	startForwarder = (*Forwarder).Start

	var mu sync.Mutex
	type listen struct {
		port int
		ln   net.Listener
	}
	var opened []listen
	var targets []map[int]string
	var vipPorts [][]int
	orig := openServiceListener
	t.Cleanup(func() {
		tm.m.stopRule("app", true)
		openServiceListener = orig
	})
	openServiceListener = func(srv *tsnet.Server, name string, mode tsnet.ServiceMode) (net.Listener, error) {
		tcp := mode.(tsnet.ServiceModeTCP)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		mu.Lock()
		opened = append(opened, listen{port: int(tcp.Port), ln: ln})
		mu.Unlock()
		return ln, nil
	}
	wrap := startForwarder
	startForwarder = func(f *Forwarder, ctx context.Context) error {
		mu.Lock()
		targets = append(targets, maps.Clone(f.localTargets))
		vipPorts = append(vipPorts, slices.Clone(f.vip.Ports))
		mu.Unlock()
		return wrap(f, ctx)
	}

	base := *tm.m.cfg
	base.InstanceID = testOwner
	base.PollInterval = config.Duration{Duration: time.Hour}
	base.DialTimeout = config.Duration{Duration: time.Second}
	with := func(r ...config.BridgeRule) *config.Config {
		c := base
		c.Bridges = r
		return &c
	}
	rule := config.BridgeRule{
		Name: "app", DestTailnets: []string{"dest"},
		LocalSources: []config.LocalSourceSpec{{
			Addr: "10.0.0.1", DNSName: "app.example.com", ShortName: "app",
			Ports: config.LocalPortList(80, 443),
		}},
	}
	ctx := context.Background()
	id := "app/local/dest/10.0.0.1/app"
	tm.m.Reconcile(ctx, with(rule))
	waitFor(t, 5*time.Second, "multi-port bridge active", func() bool { return tm.bridgeActive(id) })

	svc, ok := tm.dest.Service("svc:app")
	if !ok || !slices.Equal(svc.Ports, []string{"tcp:80", "tcp:443"}) {
		t.Fatalf("advertised ports = %v, ok=%v", svc.Ports, ok)
	}
	mu.Lock()
	if len(opened) != 2 || !slices.Equal(vipPorts[0], []int{80, 443}) {
		t.Fatalf("listens = %+v vip ports %v", opened, vipPorts)
	}
	if targets[0][80] != "10.0.0.1:80" || targets[0][443] != "10.0.0.1:443" {
		t.Fatalf("targets = %v", targets[0])
	}
	first := append([]listen(nil), opened...)
	mu.Unlock()

	tm.dest.ResetCalls()
	changed := rule
	changed.LocalSources = []config.LocalSourceSpec{{
		Addr: "10.0.0.1", DNSName: "app.example.com", ShortName: "app",
		Ports: config.LocalPortMap(map[int]int{80: 8080}),
	}}
	tm.m.Reconcile(ctx, with(changed))
	waitFor(t, 5*time.Second, "bridge active after port change", func() bool { return tm.bridgeActive(id) })
	for _, w := range callStrings(tm.dest.Writes()) {
		if strings.HasPrefix(w, "DELETE") {
			t.Errorf("port change deleted a service: %s", w)
		}
	}
	svc, _ = tm.dest.Service("svc:app")
	if !slices.Equal(svc.Ports, []string{"tcp:80"}) {
		t.Fatalf("ports after change = %v", svc.Ports)
	}
	mu.Lock()
	if len(vipPorts) < 2 || !slices.Equal(vipPorts[len(vipPorts)-1], []int{80}) {
		t.Fatalf("re-listen ports = %v", vipPorts)
	}
	if targets[len(targets)-1][80] != "10.0.0.1:8080" {
		t.Fatalf("targets after change = %v", targets[len(targets)-1])
	}
	later := append([]listen(nil), opened[len(first):]...)
	mu.Unlock()
	for _, ln := range first {
		if c, err := net.DialTimeout("tcp", ln.ln.Addr().String(), 200*time.Millisecond); err == nil {
			c.Close()
			t.Errorf("port %d listener still open after the port set changed", ln.port)
		}
	}
	if len(later) != 1 || later[0].port != 80 {
		t.Fatalf("re-listen = %+v", later)
	}

	tm.m.Reconcile(ctx, with())
	waitFor(t, 5*time.Second, "service removed", func() bool {
		_, exists := tm.dest.Service("svc:app")
		return !exists
	})
	if c, err := net.DialTimeout("tcp", later[0].ln.Addr().String(), 200*time.Millisecond); err == nil {
		c.Close()
		t.Error("listener still open after the rule was removed")
	}
}

func TestLocalListenFailureRemovesService(t *testing.T) {
	tm := newTestManager(t)
	startForwarder = (*Forwarder).Start
	var mu sync.Mutex
	var first net.Listener
	orig := openServiceListener
	t.Cleanup(func() {
		tm.m.stopRule("app", true)
		openServiceListener = orig
	})
	openServiceListener = func(srv *tsnet.Server, name string, mode tsnet.ServiceMode) (net.Listener, error) {
		tcp := mode.(tsnet.ServiceModeTCP)
		if tcp.Port == 443 {
			return nil, errors.New("second port failed")
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		mu.Lock()
		first = ln
		mu.Unlock()
		return ln, nil
	}
	base := *tm.m.cfg
	base.InstanceID = testOwner
	cfg := base
	cfg.Bridges = []config.BridgeRule{{
		Name: "app", DestTailnets: []string{"dest"},
		LocalSources: []config.LocalSourceSpec{{
			Addr: "10.0.0.1", DNSName: "app.example.com", ShortName: "app",
			Ports: config.LocalPortList(80, 443),
		}},
	}}
	tm.m.Reconcile(context.Background(), &cfg)
	var failed net.Listener
	waitFor(t, 5*time.Second, "failed listen rolled back", func() bool {
		mu.Lock()
		failed = first
		mu.Unlock()
		_, ok := tm.dest.Service("svc:app")
		return !ok && failed != nil
	})
	if c, err := net.DialTimeout("tcp", failed.Addr().String(), 200*time.Millisecond); err == nil {
		c.Close()
		t.Error("port 80 listener still open after port 443 failed to listen")
	}
}
