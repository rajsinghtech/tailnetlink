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

// listenDNS hosts the DNS VIP. Tests replace it so DNS setup can run
// without a live tsnet node. Production goes through the serialized listen.
var listenDNS = listenServiceWithRetry

// DNSServer is an authoritative DNS server for one zone in one destination
// tailnet, shared by every rule that publishes names in that zone. It is
// exposed as a Tailscale VIP service on TCP:53 so split-DNS can point at a
// stable VIP rather than the node's own address.
//
// It answers over TCP only. tsnet hands a service host only the TCP
// connections for its VIPs (UDP to a VIP is dropped), so there is nothing
// to serve UDP on. Clients don't notice: they ask 100.100.100.100 over UDP
// or TCP as usual, and their resolver retries the split-DNS upstream over
// TCP when UDP gets no answer.
type DNSServer struct {
	srv       *tsnet.Server
	apiClient *tsclient.Client
	destTags  []string
	owner     string
	zone      string // FQDN with trailing dot e.g. "keiretsu.ts.net."
	logger    *slog.Logger

	mu      sync.RWMutex
	records map[string]netip.Addr // FQDN (trailing dot) → IP (v4 or v6)

	svcName   string
	mux       *dns.ServeMux
	tcpServer *dns.Server
}

// NewDNSServer returns a server for zone. Its VIP service is named after the
// zone, svc:tnl-dns-<zone>-dns, so every rule that puts names in the zone
// shares it.
func NewDNSServer(srv *tsnet.Server, apiClient *tsclient.Client, destTags []string, owner, zone string, logger *slog.Logger) *DNSServer {
	d := &DNSServer{
		srv:       srv,
		apiClient: apiClient,
		destTags:  destTags,
		owner:     owner,
		zone:      dns.Fqdn(zone),
		logger:    logger,
		records:   make(map[string]netip.Addr),
	}
	d.svcName = DNSServiceName(zone)
	d.mux = dns.NewServeMux()
	d.mux.HandleFunc(d.zone, d.handle)
	return d
}

// DNSServiceName is the VIP service that serves zone.
func DNSServiceName(zone string) string {
	return "svc:" + capLabel("tnl-dns-"+sanitize(strings.TrimSuffix(zone, "."))+"-dns", 59)
}

// Start creates a VIP service for DNS, registers this tsnet node as its TCP:53
// host via ListenService, and returns the VIP IP to use as the split-DNS
// resolver address.
func (d *DNSServer) Start(ctx context.Context) (netip.Addr, error) {
	zone := strings.TrimSuffix(d.zone, ".")
	created, err := ensureVIPService(ctx, d.apiClient, d.owner, tsclient.VIPService{
		Name:    d.svcName,
		Ports:   []string{"tcp:53"},
		Tags:    d.destTags,
		Comment: fmt.Sprintf("managed by tailnetlink (DNS for %s)", zone),
		Annotations: map[string]string{
			"tailnetlink/zone": zone,
		},
	})
	if err != nil {
		return netip.Addr{}, err
	}

	vipIP, ok := firstIP(created.Addrs)
	if !ok {
		return netip.Addr{}, fmt.Errorf("DNS VIP service %q has no assigned IP address", d.svcName)
	}

	ln, err := listenDNS(d.srv, d.svcName, tsnet.ServiceModeTCP{Port: 53})
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

// DeleteService removes the DNS VIP service from the destination tailnet,
// if this instance still owns it.
func (d *DNSServer) DeleteService(ctx context.Context) error {
	if err := deleteOwnedVIPService(ctx, d.apiClient, d.owner, d.svcName); err != nil {
		d.logger.Warn("failed to delete DNS VIP service", "service", d.svcName, "err", err)
		return err
	}
	d.logger.Info("DNS VIP service deleted", "service", d.svcName)
	return nil
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
