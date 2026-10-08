package bridge

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"
	"unsafe"

	mdns "github.com/miekg/dns"
	"tailscale.com/ipn"
	"tailscale.com/net/dns"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tsnet"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/preftype"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

// advertised is one subnet route a peer is offering. It is not installed
// until a via:tailnet target needs it.
type advertised struct {
	peer   key.NodePublic
	prefix netip.Prefix
}

// minimalCover is the most specific advertised prefix that contains ip.
// A tailscale IP needs no subnet route. ok is false when nothing covers ip.
func minimalCover(routes []advertised, ip netip.Addr) (netip.Prefix, key.NodePublic, bool) {
	if !ip.IsValid() || tsaddr.IsTailscaleIP(ip) {
		return netip.Prefix{}, key.NodePublic{}, false
	}
	var best netip.Prefix
	var owner key.NodePublic
	for _, r := range routes {
		if !r.prefix.IsValid() || !r.prefix.Contains(ip) {
			continue
		}
		if !best.IsValid() || r.prefix.Bits() > best.Bits() {
			best = r.prefix
			owner = r.peer
		}
	}
	return best, owner, best.IsValid()
}

func tailscaleRoute(p netip.Prefix) bool {
	if !p.IsValid() {
		return false
	}
	ip := p.Addr()
	if p.IsSingleIP() && tsaddr.IsTailscaleIP(ip) {
		return true
	}
	return p == tsaddr.CGNATRange() || p == tsaddr.TailscaleULARange()
}

// nodeScope is the source node's userspace view of which subnet prefixes
// this process has installed. It never edits prefs, policy, or any other
// device. RouteAll stays off.
type nodeScope struct {
	mu      sync.Mutex
	srv     *tsnet.Server
	nm      *netmap.NetworkMap
	want    []string // configured hosts: IPs or names
	applied []netip.Prefix
	touched bool
	watch   bool
	cancel  context.CancelFunc
}

func (m *Manager) scopeFor(name string, srv *tsnet.Server) *nodeScope {
	m.mu.Lock()
	if m.scopes == nil {
		m.scopes = map[string]*nodeScope{}
	}
	sc := m.scopes[name]
	if sc == nil {
		sc = &nodeScope{}
		m.scopes[name] = sc
	}
	m.mu.Unlock()
	if srv != nil {
		sc.mu.Lock()
		sc.srv = srv
		sc.mu.Unlock()
	}
	return sc
}

func (m *Manager) dropScope(name string) {
	m.mu.Lock()
	sc := m.scopes[name]
	delete(m.scopes, name)
	m.mu.Unlock()
	if sc == nil {
		return
	}
	sc.mu.Lock()
	cancel := sc.cancel
	sc.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// syncTailnetDial installs or withdraws the subnet prefixes this node's
// via:tailnet entries need. A tailnet with no such entries is left alone.
func (m *Manager) syncTailnetDial(ctx context.Context, name string) {
	m.mu.Lock()
	srv := m.servers[name]
	var hosts []string
	if m.cfg != nil {
		for _, rule := range m.cfg.Bridges {
			if rule.SourceTailnet != name {
				continue
			}
			for _, src := range rule.LocalSources {
				if src.DialVia() != "tailnet" {
					continue
				}
				host, _, err := src.Forwards()
				if err != nil {
					continue
				}
				hosts = append(hosts, host)
			}
		}
	}
	m.mu.Unlock()
	if srv == nil {
		return
	}
	sc := m.scopeFor(name, srv)
	sc.mu.Lock()
	sc.want = slices.Clone(hosts)
	need := sc.touched || len(hosts) > 0
	sc.mu.Unlock()
	if !need {
		return
	}
	sc.ensureWatch(ctx)
	if err := sc.apply(ctx); err != nil {
		m.logger.Warn("scoped subnet routes", "tailnet", name, "err", err)
	}
}

func (sc *nodeScope) ensureWatch(ctx context.Context) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.watch || sc.srv == nil {
		return
	}
	sc.watch = true
	wctx, cancel := context.WithCancel(ctx)
	sc.cancel = cancel
	srv := sc.srv
	go func() {
		lc, err := srv.LocalClient()
		if err != nil {
			return
		}
		watcher, err := lc.WatchIPNBus(wctx, ipn.NotifyInitialNetMap)
		if err != nil {
			return
		}
		defer watcher.Close()
		for {
			n, err := watcher.Next()
			if err != nil {
				return
			}
			if n.NetMap == nil {
				continue
			}
			sc.mu.Lock()
			sc.nm = n.NetMap
			sc.mu.Unlock()
			_ = sc.apply(wctx)
		}
	}()
}

func (sc *nodeScope) server() *tsnet.Server {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.srv
}

func (sc *nodeScope) netmap() *netmap.NetworkMap {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.nm
}

func (sc *nodeScope) wantedHosts() []string {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return slices.Clone(sc.want)
}

// apply installs the minimal advertised prefixes that cover configured
// addresses and the split-DNS resolvers needed to look those names up.
// An empty target list removes any prefixes this process installed.
func (sc *nodeScope) apply(ctx context.Context) error {
	hosts := sc.wantedHosts()
	nm := sc.netmap()
	if len(hosts) == 0 {
		sc.mu.Lock()
		touched := sc.touched
		sc.mu.Unlock()
		if !touched {
			return nil
		}
		if err := installSubnetRoutes(sc.server(), nil, nil); err != nil {
			return err
		}
		sc.mu.Lock()
		sc.applied = nil
		sc.mu.Unlock()
		return nil
	}
	if nm == nil {
		return errors.New("source netmap not ready")
	}
	routes := advertisedRoutes(nm)
	want, owners := prefixesFor(routes, hosts, nm)
	if err := installSubnetRoutes(sc.server(), want, owners); err != nil {
		return err
	}
	sc.mu.Lock()
	sc.applied = want
	sc.touched = true
	sc.mu.Unlock()
	return nil
}

// accepted returns the subnet prefixes currently installed for this node.
func (sc *nodeScope) accepted() []netip.Prefix {
	got, err := installedSubnetRoutes(sc.server())
	if err != nil {
		sc.mu.Lock()
		defer sc.mu.Unlock()
		return slices.Clone(sc.applied)
	}
	return got
}

func (m *Manager) AcceptedRoutes(tailnet string) []netip.Prefix {
	m.mu.Lock()
	sc := m.scopes[tailnet]
	m.mu.Unlock()
	if sc == nil {
		return nil
	}
	return sc.accepted()
}

// DialSource dials addr through the source node without widening the set of
// accepted prefixes. An address outside the installed prefixes is refused
// before a packet is sent.
func (m *Manager) DialSource(ctx context.Context, tailnet, addr string) (net.Conn, error) {
	m.mu.Lock()
	srv := m.servers[tailnet]
	m.mu.Unlock()
	if srv == nil {
		return nil, fmt.Errorf("tailnet %q is not connected", tailnet)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, err
	}
	if !tsaddr.IsTailscaleIP(ip) && !prefixContains(m.AcceptedRoutes(tailnet), ip) {
		return nil, fmt.Errorf("%w: %s", errNoSubnetRoute, ip)
	}
	return tailnetDial(ctx, srv, "tcp", addr)
}

func prefixContains(ps []netip.Prefix, ip netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func dedupePrefixes(in []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range in {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	tsaddr.SortPrefixes(out)
	return out
}

func advertisedRoutes(nm *netmap.NetworkMap) []advertised {
	if nm == nil {
		return nil
	}
	var out []advertised
	for _, p := range nm.Peers {
		pr := p.PrimaryRoutes()
		for i := range pr.Len() {
			out = append(out, advertised{peer: p.Key(), prefix: pr.At(i)})
		}
	}
	return out
}

func splitResolverIPs(nm *netmap.NetworkMap, host string) []netip.Addr {
	if nm == nil || nm.DNS.Routes == nil {
		return nil
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	best := ""
	var resolvers []string
	for suffix, rs := range nm.DNS.Routes {
		s := strings.TrimSuffix(strings.ToLower(suffix), ".")
		if host != s && !strings.HasSuffix(host, "."+s) {
			continue
		}
		if len(s) < len(best) {
			continue
		}
		best = s
		resolvers = resolvers[:0]
		for _, r := range rs {
			if r == nil || r.Addr == "" {
				continue
			}
			resolvers = append(resolvers, r.Addr)
		}
	}
	var ips []netip.Addr
	for _, addr := range resolvers {
		ip := addr
		if h, _, err := net.SplitHostPort(addr); err == nil {
			ip = h
		}
		parsed, err := netip.ParseAddr(ip)
		if err == nil {
			ips = append(ips, parsed)
		}
	}
	return ips
}

// resolveTailnetHost resolves host as a client of the source node.
// MagicDNS names use the netmap. Other names use the tailnet's split-DNS
// routes; the query is sent through the userspace netstack, not the system
// resolver. The pod resolver is never consulted.
func (m *Manager) resolveTailnetHost(ctx context.Context, tailnet string, srv *tsnet.Server, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip, nil
	}
	sc := m.scopeFor(tailnet, srv)
	nm := sc.netmap()
	if nm == nil {
		return netip.Addr{}, errors.New("source netmap not ready")
	}
	if ip, ok := magicDNSAddr(nm, host); ok {
		return ip, nil
	}
	resolvers := splitResolverIPs(nm, host)
	if len(resolvers) == 0 {
		return netip.Addr{}, fmt.Errorf("name %q is not in the source tailnet MagicDNS or split DNS", host)
	}
	var last error
	for _, ns := range resolvers {
		if err := sc.cover(ctx, ns); err != nil {
			last = err
			continue
		}
		ip, err := queryA(ctx, srv, ns, host)
		if err != nil {
			last = err
			continue
		}
		if err := sc.cover(ctx, ip); err != nil {
			return netip.Addr{}, err
		}
		return ip, nil
	}
	if last == nil {
		last = fmt.Errorf("no split-DNS answer for %q", host)
	}
	return netip.Addr{}, last
}

// cover installs the advertised prefix for ip if it is a subnet address.
func (sc *nodeScope) cover(ctx context.Context, ip netip.Addr) error {
	if tsaddr.IsTailscaleIP(ip) {
		return nil
	}
	nm := sc.netmap()
	p, _, ok := minimalCover(advertisedRoutes(nm), ip)
	if !ok {
		return fmt.Errorf("%w: %s", errNoSubnetRoute, ip)
	}
	sc.mu.Lock()
	already := slices.Contains(sc.applied, p)
	sc.mu.Unlock()
	if already {
		return nil
	}
	routes := advertisedRoutes(nm)
	_, owner, _ := minimalCover(routes, ip)
	sc.mu.Lock()
	sc.applied = dedupePrefixes(append(sc.applied, p))
	want := slices.Clone(sc.applied)
	sc.touched = true
	sc.mu.Unlock()
	owners := map[netip.Prefix]key.NodePublic{p: owner}
	for _, have := range want {
		if _, ok := owners[have]; !ok {
			if _, who, ok := minimalCover(routes, have.Addr()); ok {
				owners[have] = who
			}
		}
	}
	return installSubnetRoutes(sc.server(), want, owners)
}

func prefixesFor(routes []advertised, hosts []string, nm *netmap.NetworkMap) ([]netip.Prefix, map[netip.Prefix]key.NodePublic) {
	owners := map[netip.Prefix]key.NodePublic{}
	var want []netip.Prefix
	add := func(ip netip.Addr) {
		p, owner, ok := minimalCover(routes, ip)
		if !ok {
			return
		}
		want = append(want, p)
		owners[p] = owner
	}
	for _, host := range hosts {
		if ip, err := netip.ParseAddr(host); err == nil {
			add(ip)
			continue
		}
		for _, ip := range splitResolverIPs(nm, host) {
			add(ip)
		}
	}
	return dedupePrefixes(want), owners
}

func magicDNSAddr(nm *netmap.NetworkMap, host string) (netip.Addr, bool) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, p := range nm.Peers {
		name := strings.TrimSuffix(strings.ToLower(p.Name()), ".")
		if name != host {
			continue
		}
		for i := range p.Addresses().Len() {
			a := p.Addresses().At(i).Addr()
			if a.Is4() && tsaddr.IsTailscaleIP(a) {
				return a, true
			}
		}
	}
	return netip.Addr{}, false
}

func queryA(ctx context.Context, srv *tsnet.Server, ns netip.Addr, host string) (netip.Addr, error) {
	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(host), mdns.TypeA)
	msg.RecursionDesired = true
	packed, err := msg.Pack()
	if err != nil {
		return netip.Addr{}, err
	}
	var buf []byte
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(packed)))
	buf = append(buf, packed...)
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := tailnetDial(dctx, srv, "tcp", net.JoinHostPort(ns.String(), "53"))
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()
	if dl, ok := dctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write(buf); err != nil {
		return netip.Addr{}, err
	}
	var nbuf [2]byte
	if _, err := io.ReadFull(conn, nbuf[:]); err != nil {
		return netip.Addr{}, err
	}
	n := int(binary.BigEndian.Uint16(nbuf[:]))
	if n <= 0 || n > 65535 {
		return netip.Addr{}, fmt.Errorf("bad dns length %d", n)
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(conn, raw); err != nil {
		return netip.Addr{}, err
	}
	var resp mdns.Msg
	if err := resp.Unpack(raw); err != nil {
		return netip.Addr{}, err
	}
	for _, rr := range resp.Answer {
		if a, ok := rr.(*mdns.A); ok && a.A != nil {
			ip, ok := netip.AddrFromSlice(a.A.To4())
			if ok {
				return ip, nil
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("no A record for %q", host)
}

// installSubnetRoutes rewrites this node's userspace WireGuard allowed IPs
// so the only subnet prefixes present are want. Tailscale node addresses
// stay. Nothing is written to the control plane, to other devices, or to
// the host routing table: tsnet is on its fake TUN and netstack.
func installSubnetRoutes(srv *tsnet.Server, want []netip.Prefix, owners map[netip.Prefix]key.NodePublic) error {
	if srv == nil || srv.Sys() == nil {
		return errors.New("source node is not running")
	}
	eng, ok := srv.Sys().Engine.GetOK()
	if !ok || eng == nil {
		return errors.New("source engine is not running")
	}
	cfg, rc, dnsCfg, err := readEngineConfig(eng)
	if err != nil {
		return err
	}
	want = dedupePrefixes(want)
	if slices.Equal(subnetPrefixes(cfg), want) {
		return nil
	}
	cfg = scopeAllowedIPs(cfg, want, owners)
	rc = scopeRouter(rc, cfg, want)
	err = eng.Reconfig(cfg, rc, dnsCfg)
	if err != nil && !errors.Is(err, wgengine.ErrNoChanges) {
		return err
	}
	return nil
}

func installedSubnetRoutes(srv *tsnet.Server) ([]netip.Prefix, error) {
	if srv == nil || srv.Sys() == nil {
		return nil, errors.New("source node is not running")
	}
	eng, ok := srv.Sys().Engine.GetOK()
	if !ok || eng == nil {
		return nil, errors.New("source engine is not running")
	}
	cfg, _, _, err := readEngineConfig(eng)
	if err != nil {
		return nil, err
	}
	return subnetPrefixes(cfg), nil
}

func subnetPrefixes(cfg *wgcfg.Config) []netip.Prefix {
	if cfg == nil {
		return nil
	}
	var out []netip.Prefix
	for _, p := range cfg.Peers {
		for _, aip := range p.AllowedIPs {
			if !tailscaleRoute(aip) {
				out = append(out, aip)
			}
		}
	}
	return dedupePrefixes(out)
}

func scopeAllowedIPs(cfg *wgcfg.Config, want []netip.Prefix, owners map[netip.Prefix]key.NodePublic) *wgcfg.Config {
	if cfg == nil {
		return &wgcfg.Config{}
	}
	out := *cfg
	out.Peers = slices.Clone(cfg.Peers)
	for i, p := range out.Peers {
		var keep []netip.Prefix
		for _, aip := range p.AllowedIPs {
			if tailscaleRoute(aip) {
				keep = append(keep, aip)
			}
		}
		for _, w := range want {
			if owners[w] == p.PublicKey {
				keep = append(keep, w)
			}
		}
		p.AllowedIPs = dedupePrefixes(keep)
		out.Peers[i] = p
	}
	return &out
}

func scopeRouter(rc *router.Config, cfg *wgcfg.Config, want []netip.Prefix) *router.Config {
	out := &router.Config{NetfilterMode: preftype.NetfilterOff}
	if rc != nil {
		out = rc.Clone()
		out.NetfilterMode = preftype.NetfilterOff
	}
	if cfg != nil && len(out.LocalAddrs) == 0 {
		out.LocalAddrs = slices.Clone(cfg.Addresses)
	}
	var routes []netip.Prefix
	for _, r := range out.Routes {
		if tailscaleRoute(r) {
			routes = append(routes, r)
		}
	}
	routes = append(routes, want...)
	out.Routes = dedupePrefixes(routes)
	return out
}

func readEngineConfig(eng wgengine.Engine) (*wgcfg.Config, *router.Config, *dns.Config, error) {
	u := userspaceValue(eng)
	if !u.IsValid() {
		return nil, nil, nil, fmt.Errorf("source engine %T is not the userspace engine", eng)
	}
	lock := mutexAt(u.FieldByName("wgLock"))
	lock.Lock()
	defer lock.Unlock()
	cfg := exportField(u.FieldByName("lastCfgFull")).Interface().(wgcfg.Config)
	cfg.Peers = slices.Clone(cfg.Peers)
	for i := range cfg.Peers {
		cfg.Peers[i].AllowedIPs = slices.Clone(cfg.Peers[i].AllowedIPs)
	}
	var rc *router.Config
	rf := u.FieldByName("lastRouter")
	if rf.IsValid() && !rf.IsNil() {
		rc = exportField(rf).Interface().(*router.Config).Clone()
	}
	var dnsCfg dns.Config
	df := exportField(u.FieldByName("lastDNSConfig"))
	if view, ok := df.Interface().(dns.ConfigView); ok && view.Valid() {
		dnsCfg = *view.AsStruct()
	}
	return &cfg, rc, &dnsCfg, nil
}

func userspaceValue(eng wgengine.Engine) reflect.Value {
	v := reflect.ValueOf(eng)
	for i := 0; i < 4; i++ {
		if !v.IsValid() || v.IsNil() {
			return reflect.Value{}
		}
		if v.Kind() == reflect.Interface {
			v = v.Elem()
			continue
		}
		if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
			return reflect.Value{}
		}
		if v.Elem().FieldByName("lastCfgFull").IsValid() {
			return v.Elem()
		}
		w := v.Elem().FieldByName("wrap")
		if w.IsValid() && !w.IsNil() {
			v = w
			continue
		}
		return reflect.Value{}
	}
	return reflect.Value{}
}

func exportField(f reflect.Value) reflect.Value {
	if !f.IsValid() {
		return f
	}
	if f.CanInterface() {
		return f
	}
	return reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem()
}

func mutexAt(f reflect.Value) *sync.Mutex {
	return (*sync.Mutex)(unsafe.Pointer(f.UnsafeAddr()))
}
