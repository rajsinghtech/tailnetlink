package bridge

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"tailscale.com/tsnet"
)

// listenRetryDelay is the base pause between listen retries. Tests set it
// to zero so retries don't wait.
var listenRetryDelay = 150 * time.Millisecond

const listenAttempts = 8

// nodeBinding ties a tsnet node to the manager that hosts it, so a listen
// can update the advertised-vs-desired gauge without every caller knowing
// about metrics.
type nodeBinding struct {
	m       *Manager
	tailnet string
}

var (
	nodeBindings sync.Map // *tsnet.Server -> *nodeBinding
	listenLocks  sync.Map // *tsnet.Server -> *sync.Mutex
)

func (m *Manager) bindNode(tailnet string, srv *tsnet.Server) {
	if m == nil || srv == nil || tailnet == "" {
		return
	}
	nodeBindings.Store(srv, &nodeBinding{m: m, tailnet: tailnet})
}

func (m *Manager) unbindNode(tailnet string, srv *tsnet.Server) {
	if srv != nil {
		nodeBindings.Delete(srv)
		listenLocks.Delete(srv)
	}
	m.forgetTailnet(tailnet)
}

func lookupNode(srv *tsnet.Server) *nodeBinding {
	v, ok := nodeBindings.Load(srv)
	if !ok {
		return nil
	}
	return v.(*nodeBinding)
}

func listenLock(srv *tsnet.Server) *sync.Mutex {
	v, _ := listenLocks.LoadOrStore(srv, new(sync.Mutex))
	return v.(*sync.Mutex)
}

type listenFunc func(*tsnet.Server, string, tsnet.ServiceMode) (net.Listener, error)
type advertisedFunc func(*tsnet.Server, string) (bool, error)

// ListenService hosts name on srv. Calls for one node take a single lock:
// tsnet's AdvertiseServices update is a read-append-write with no lock of
// its own, so overlapping calls drop names and the VIP cannot be routed.
// The listener is returned only after name is in AdvertiseServices.
func ListenService(srv *tsnet.Server, name string, mode tsnet.ServiceMode) (net.Listener, error) {
	return listenService(srv, name, mode, func(s *tsnet.Server, n string, mode tsnet.ServiceMode) (net.Listener, error) {
		return s.ListenService(n, mode)
	}, serviceAdvertised)
}

// listenServiceWithRetry is the name callers already use.
func listenServiceWithRetry(srv *tsnet.Server, name string, mode tsnet.ServiceMode) (net.Listener, error) {
	return ListenService(srv, name, mode)
}

func listenService(srv *tsnet.Server, name string, mode tsnet.ServiceMode, open listenFunc, inPrefs advertisedFunc) (net.Listener, error) {
	if b := lookupNode(srv); b != nil {
		b.m.noteVIP(b.tailnet, name, false)
	}
	mu := listenLock(srv)
	mu.Lock()
	defer mu.Unlock()

	var last error
	for attempt := range listenAttempts {
		ln, err := open(srv, name, mode)
		if err != nil {
			last = err
			if strings.Contains(err.Error(), "etag mismatch") && attempt+1 < listenAttempts {
				time.Sleep(time.Duration(attempt+1) * listenRetryDelay)
				continue
			}
			if strings.Contains(err.Error(), "etag mismatch") {
				return nil, fmt.Errorf("listen %s: etag mismatch after retries", name)
			}
			return nil, err
		}
		ok, err := inPrefs(srv, name)
		if err == nil && ok {
			if b := lookupNode(srv); b != nil {
				b.m.noteVIP(b.tailnet, name, true)
			}
			return ln, nil
		}
		_ = ln.Close()
		if err != nil {
			last = err
		} else {
			last = fmt.Errorf("listen %s: not in AdvertiseServices", name)
		}
		if attempt+1 < listenAttempts {
			time.Sleep(time.Duration(attempt+1) * listenRetryDelay)
		}
	}
	if last == nil {
		last = fmt.Errorf("listen %s: not in AdvertiseServices", name)
	}
	return nil, last
}

// serviceAdvertised reports whether name is in the node's advertised
// service list. A short poll covers the localapi copy lagging the write
// that ListenService just made; the node lock is held across it so no
// other listen can interleave.
func serviceAdvertised(srv *tsnet.Server, name string) (bool, error) {
	lc, err := srv.LocalClient()
	if err != nil {
		return false, err
	}
	var last error
	for try := range 5 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		prefs, err := lc.GetPrefs(ctx)
		cancel()
		if err != nil {
			last = err
		} else if slices.Contains(prefs.AdvertiseServices, name) {
			return true, nil
		}
		if try+1 < 5 {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if last != nil {
		return false, last
	}
	return false, nil
}

func (m *Manager) noteVIP(tailnet, name string, advertised bool) {
	if m == nil || tailnet == "" || name == "" {
		return
	}
	m.vipMu.Lock()
	defer m.vipMu.Unlock()
	if m.vipDesired == nil {
		m.vipDesired = map[string]map[string]struct{}{}
	}
	if m.vipDesired[tailnet] == nil {
		m.vipDesired[tailnet] = map[string]struct{}{}
	}
	m.vipDesired[tailnet][name] = struct{}{}
	if !advertised {
		return
	}
	if m.vipAdvertised == nil {
		m.vipAdvertised = map[string]map[string]struct{}{}
	}
	if m.vipAdvertised[tailnet] == nil {
		m.vipAdvertised[tailnet] = map[string]struct{}{}
	}
	m.vipAdvertised[tailnet][name] = struct{}{}
}

func (m *Manager) dropAdvertised(tailnet, name string) {
	if m == nil || tailnet == "" || name == "" {
		return
	}
	m.vipMu.Lock()
	defer m.vipMu.Unlock()
	deleteName(m.vipAdvertised, tailnet, name)
}

func (m *Manager) forgetVIP(tailnet, name string) {
	if m == nil || tailnet == "" || name == "" {
		return
	}
	m.vipMu.Lock()
	defer m.vipMu.Unlock()
	deleteName(m.vipDesired, tailnet, name)
	deleteName(m.vipAdvertised, tailnet, name)
}

func (m *Manager) forgetTailnet(tailnet string) {
	if m == nil || tailnet == "" {
		return
	}
	m.vipMu.Lock()
	defer m.vipMu.Unlock()
	delete(m.vipDesired, tailnet)
	delete(m.vipAdvertised, tailnet)
}

func deleteName(sets map[string]map[string]struct{}, tailnet, name string) {
	delete(sets[tailnet], name)
	if len(sets[tailnet]) == 0 {
		delete(sets, tailnet)
	}
}

func (m *Manager) vipCounts() (desired, advertised map[string]int) {
	m.vipMu.Lock()
	defer m.vipMu.Unlock()
	desired = make(map[string]int, len(m.vipDesired))
	for tn, set := range m.vipDesired {
		if n := len(set); n > 0 {
			desired[tn] = n
		}
	}
	advertised = make(map[string]int, len(m.vipAdvertised))
	for tn, set := range m.vipAdvertised {
		if n := len(set); n > 0 {
			advertised[tn] = n
		}
	}
	return desired, advertised
}
