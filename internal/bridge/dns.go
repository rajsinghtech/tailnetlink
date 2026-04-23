package bridge

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"

	"github.com/miekg/dns"
	tsclient "tailscale.com/client/tailscale/v2"
	"tailscale.com/tsnet"
)

// DNSServer is an authoritative DNS server for a bridge zone. It is exposed as
// a Tailscale VIP service (TCP+UDP:53) so that Tailscale split-DNS can route zone
// queries to a stable VIP IP rather than the ephemeral tsnet node IP.
type DNSServer struct {
	srv       *tsnet.Server
	apiClient *tsclient.Client
	ruleName  string
	destTags  []string
	zone      string // FQDN with trailing dot e.g. "keiretsu.ts.net."
	logger    *slog.Logger

	mu      sync.RWMutex
	records map[string]netip.Addr // FQDN (trailing dot) → IP (v4 or v6)

	svcName   string // populated by Start
	mux       *dns.ServeMux
	tcpServer *dns.Server
	udpServer *dns.Server
}

func NewDNSServer(srv *tsnet.Server, apiClient *tsclient.Client, ruleName string, destTags []string, zone string, logger *slog.Logger) *DNSServer {
	d := &DNSServer{
		srv:       srv,
		apiClient: apiClient,
		ruleName:  ruleName,
		destTags:  destTags,
		zone:      dns.Fqdn(zone),
		logger:    logger,
		records:   make(map[string]netip.Addr),
	}
	d.mux = dns.NewServeMux()
	d.mux.HandleFunc(d.zone, d.handle)
	return d
}

// Start creates a VIP service for DNS, registers this tsnet node as its TCP:53
// host via ListenService, and returns the VIP IP to use as the split-DNS
// resolver address.
func (d *DNSServer) Start(ctx context.Context) (netip.Addr, error) {
	d.svcName = fmt.Sprintf("svc:tnl-%s-dns", sanitize(d.ruleName))

	created, err := ensureVIPService(ctx, d.apiClient, tsclient.VIPService{
		Name:    d.svcName,
		Ports:   []string{"tcp:53"},
		Tags:    d.destTags,
		Comment: fmt.Sprintf("managed by tailnetlink (DNS, rule: %s)", d.ruleName),
		Annotations: map[string]string{
			"tailnetlink/managed": "true",
			"tailnetlink/rule":    d.ruleName,
		},
	})
	if err != nil {
		return netip.Addr{}, err
	}

	vipIP, ok := firstIP(created.Addrs)
	if !ok {
		return netip.Addr{}, fmt.Errorf("DNS VIP service %q has no assigned IP address", d.svcName)
	}

	ln, err := listenServiceWithRetry(d.srv, d.svcName, tsnet.ServiceModeTCP{Port: 53})
	if err != nil {
		return netip.Addr{}, fmt.Errorf("dns listen service tcp: %w", err)
	}

	d.tcpServer = &dns.Server{Listener: ln, Handler: d.mux}

	go func() {
		if err := d.tcpServer.ActivateAndServe(); err != nil {
			d.logger.Error("DNS TCP server stopped", "zone", d.zone, "err", err)
		}
	}()

	d.logger.Info("DNS VIP service listening", "zone", d.zone, "vip", vipIP, "service", d.svcName)
	return vipIP, nil
}

// Stop shuts down the TCP DNS server.
func (d *DNSServer) Stop() {
	if d.tcpServer != nil {
		_ = d.tcpServer.Shutdown()
	}
}

// DeleteService removes the DNS VIP service from the destination tailnet.
func (d *DNSServer) DeleteService(ctx context.Context) {
	if d.svcName == "" {
		return
	}
	if err := d.apiClient.VIPServices().Delete(ctx, d.svcName); err != nil {
		d.logger.Warn("failed to delete DNS VIP service", "service", d.svcName, "err", err)
	} else {
		d.logger.Info("DNS VIP service deleted", "service", d.svcName)
	}
}

// AddRecord registers a short hostname → VIP mapping in the zone.
func (d *DNSServer) AddRecord(hostname string, ip netip.Addr) {
	fqdn := d.recordKey(hostname)
	d.mu.Lock()
	d.records[fqdn] = ip.Unmap()
	d.mu.Unlock()
}

// RemoveRecord removes a hostname from the zone.
func (d *DNSServer) RemoveRecord(hostname string) {
	fqdn := d.recordKey(hostname)
	d.mu.Lock()
	delete(d.records, fqdn)
	d.mu.Unlock()
}

// recordKey returns the DNS FQDN key for a hostname within this zone.
// When hostname equals the zone name (or "@"), the record is at the apex.
func (d *DNSServer) recordKey(hostname string) string {
	zoneName := strings.TrimSuffix(d.zone, ".")
	if hostname == zoneName || hostname == "@" {
		return d.zone
	}
	return dns.Fqdn(hostname + "." + zoneName)
}

func (d *DNSServer) handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
			continue
		}
		d.mu.RLock()
		ip, ok := d.records[q.Name]
		d.mu.RUnlock()
		if !ok {
			m.SetRcode(r, dns.RcodeNameError)
			break
		}
		switch {
		case q.Qtype == dns.TypeA && ip.Is4():
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   ip.AsSlice(),
			})
		case q.Qtype == dns.TypeAAAA && ip.Is6():
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: ip.AsSlice(),
			})
		}
		// If the record exists but doesn't match the query family, return NOERROR
		// with an empty answer — standard DNS behavior for "name exists, no RRTYPE".
	}
	_ = w.WriteMsg(m)
}
