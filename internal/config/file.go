package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// PodKey is the targets.in value that dials the host network. It is not a
// tailnet, and it cannot be a tailnet key.
const PodKey = "pod"

// DefaultTag is the ACL tag a tailnet node gets when tags is left out.
var DefaultTag = []string{"tag:tailnetlink"}

// File is the only config shape. tailnets joins each network once. targets
// say what to reach. exports publish those targets into other tailnets.
type File struct {
	Name          string                 `json:"name"`
	StateDir      string                 `json:"state_dir,omitempty"`
	MetricsAddr   string                 `json:"metrics_addr,omitempty"`
	UI            UIConfigFile           `json:"ui,omitzero"`
	PollInterval  *Duration              `json:"poll_interval,omitempty"`
	DialTimeout   *Duration              `json:"dial_timeout,omitempty"`
	AuthKeyExpiry *Duration              `json:"auth_key_expiry,omitempty"`
	Authz         AuthzConfig            `json:"authz,omitzero"`
	Ephemeral     bool                   `json:"ephemeral,omitempty"`
	DNS           *OnOff                 `json:"dns,omitempty"`
	Tailnets      map[string]TailnetSpec `json:"tailnets"`
	Targets       map[string]TargetSpec  `json:"targets"`
	Exports       []ExportSpec           `json:"exports"`
}

// TailnetSpec is one tsnet node and one API login.
type TailnetSpec struct {
	Tailnet    string      `json:"tailnet"`
	Auth       OAuthCreds  `json:"auth"`
	Tags       []string    `json:"tags,omitempty"`
	ControlURL string      `json:"control_url,omitempty"`
	APIBaseURL string      `json:"api_base_url,omitempty"`
	Node       NodeSpec    `json:"node,omitzero"`
	DNS        *OnOff      `json:"dns,omitempty"`
	Authz      AuthzConfig `json:"authz,omitzero"`
}

// NodeSpec is per-tailnet node settings. State lives in the process state_dir.
type NodeSpec struct {
	Ephemeral bool   `json:"ephemeral,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
}

// TargetSpec is one thing to reach. In is a tailnet key or "pod".
type TargetSpec struct {
	In      string     `json:"in"`
	Tag     string     `json:"tag,omitempty"`
	Device  string     `json:"device,omitempty"`
	Service string     `json:"service,omitempty"`
	Addr    string     `json:"addr,omitempty"`
	Host    string     `json:"host,omitempty"`
	Ports   LocalPorts `json:"ports"`
}

// ExportSpec publishes one target into one or more tailnets.
type ExportSpec struct {
	Target  string      `json:"target"`
	To      []string    `json:"to"`
	Name    string      `json:"name,omitempty"`
	DNSName string      `json:"dns_name,omitempty"`
	DNSZone string      `json:"dns_zone,omitempty"`
	Authz   AuthzConfig `json:"authz,omitzero"`
}

// OnOff is a JSON bool. Objects are rejected: dns has no other settings.
type OnOff struct {
	On bool
}

func (o *OnOff) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	switch string(b) {
	case "true":
		o.On = true
	case "false":
		o.On = false
	default:
		return errors.New("dns must be true or false")
	}
	return nil
}

func (o OnOff) MarshalJSON() ([]byte, error) {
	if o.On {
		return []byte("true"), nil
	}
	return []byte("false"), nil
}

// oldFields are names from the previous config shapes. A file that still
// uses one of them is rejected. There is no converter.
var oldFields = map[string]bool{
	"source": true, "dest": true, "dests": true, "bridges": true, "links": true,
	"instance_id": true, "via": true, "expose_port": true, "oauth": true,
	"short_name": true, "local": true, "devices": true, "services": true, "from": true,
}

// Parse reads a tailnets/targets/exports file and compiles it.
func Parse(data []byte) (*Config, error) {
	if field, ok := findOld(data); ok {
		return nil, fmt.Errorf("the field %q is from an old config and is not used. The file has tailnets, targets, and exports. See the README", field)
	}
	var f File
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return nil, fmt.Errorf("parse config: %w. The file has tailnets, targets, and exports. See the README", err)
		}
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return f.Compile()
}

func findOld(data []byte) (string, bool) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return "", false
	}
	return walkOld(v)
}

func walkOld(v any) (string, bool) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if oldFields[k] {
				return k, true
			}
			if s, ok := walkOld(child); ok {
				return s, true
			}
		}
	case []any:
		for _, child := range t {
			if s, ok := walkOld(child); ok {
				return s, true
			}
		}
	}
	return "", false
}

// Compile checks the file and turns it into the config the process runs.
// A tailnet is joined only when a target or an export names it.
func (f *File) Compile() (*Config, error) {
	if f.Name == "" {
		return nil, errors.New("name is required: pick a short name for this process, for example \"home-work\"")
	}
	if !nameRe.MatchString(f.Name) {
		return nil, fmt.Errorf("name %q must be 1 to 40 lowercase letters, digits or dashes, starting and ending with a letter or digit", f.Name)
	}
	if err := f.Authz.validate(); err != nil {
		return nil, err
	}
	if len(f.Tailnets) == 0 {
		return nil, errors.New("tailnets is required")
	}

	cfg := defaults()
	cfg.InstanceID = f.Name
	cfg.SharedNodes = true
	cfg.StateDir = f.StateDir
	cfg.DNSDisabled = f.DNS != nil && !f.DNS.On
	cfg.UI = UIConfig{ServiceName: f.UI.ServiceName, Enabled: f.UI.Enabled}
	if f.UI.ListenAddr != "" {
		cfg.ListenAddr = f.UI.ListenAddr
	}
	if f.MetricsAddr != "" {
		cfg.MetricsAddr = f.MetricsAddr
	}
	for _, d := range []struct {
		name string
		in   *Duration
		out  *Duration
		min  time.Duration
	}{
		{"poll_interval", f.PollInterval, &cfg.PollInterval, 100 * time.Millisecond},
		{"dial_timeout", f.DialTimeout, &cfg.DialTimeout, 100 * time.Millisecond},
		{"auth_key_expiry", f.AuthKeyExpiry, &cfg.AuthKeyExpiry, time.Minute},
	} {
		if d.in == nil {
			continue
		}
		if d.in.Duration < d.min {
			return nil, fmt.Errorf("%s %s is too short (minimum %s)", d.name, d.in.Duration, d.min)
		}
		*d.out = *d.in
	}

	seenTailnet := map[string]string{}
	for _, key := range slices.Sorted(maps.Keys(f.Tailnets)) {
		if key == PodKey {
			return nil, errors.New(`tailnet key "pod" is reserved`)
		}
		if !nameRe.MatchString(key) {
			return nil, fmt.Errorf("tailnet key %q must be 1 to 40 lowercase letters, digits or dashes, starting and ending with a letter or digit", key)
		}
		tn := f.Tailnets[key]
		if err := tn.check(key); err != nil {
			return nil, err
		}
		id := strings.ToLower(strings.TrimSpace(tn.Tailnet))
		if other, ok := seenTailnet[id]; ok {
			return nil, fmt.Errorf("tailnet %q is configured more than once (keys %q and %q)", tn.Tailnet, other, key)
		}
		seenTailnet[id] = key
	}

	if f.Targets == nil {
		f.Targets = map[string]TargetSpec{}
	}
	for _, key := range slices.Sorted(maps.Keys(f.Targets)) {
		if !shortNameRe.MatchString(key) {
			return nil, fmt.Errorf("target key %q must be 1 to 63 lowercase letters, digits or dashes, starting and ending with a letter or digit", key)
		}
		if err := f.Targets[key].check(key, f.Tailnets); err != nil {
			return nil, err
		}
	}

	referenced := map[string]bool{}
	usedName := map[string]map[string]string{} // dest -> export name -> target
	seenRule := map[string]bool{}
	for i, ex := range f.Exports {
		rule, err := f.exportRule(i, ex)
		if err != nil {
			return nil, err
		}
		if seenRule[rule.Name] {
			return nil, fmt.Errorf("export %s is defined more than once; list every destination in one to array", rule.Name)
		}
		seenRule[rule.Name] = true
		tgt := f.Targets[ex.Target]
		if tgt.In != PodKey {
			referenced[tgt.In] = true
		}
		for _, dest := range rule.DestTailnets {
			referenced[dest] = true
			if usedName[dest] == nil {
				usedName[dest] = map[string]string{}
			}
			if other, ok := usedName[dest][rule.ExportName]; ok {
				return nil, fmt.Errorf("export name %q is used by target %q and target %q in tailnet %q", rule.ExportName, other, ex.Target, dest)
			}
			usedName[dest][rule.ExportName] = ex.Target
		}
		cfg.Bridges = append(cfg.Bridges, rule)
	}

	for _, key := range slices.Sorted(maps.Keys(f.Tailnets)) {
		if !referenced[key] {
			continue
		}
		tn := f.Tailnets[key]
		tags := tn.Tags
		if len(tags) == 0 {
			tags = slices.Clone(DefaultTag)
		}
		dnsOff := cfg.DNSDisabled || (tn.DNS != nil && !tn.DNS.On)
		cfg.Tailnets[key] = TailnetConfig{
			OAuth: tn.Auth, Tags: append([]string(nil), tags...), Tailnet: tn.Tailnet,
			Ephemeral: f.Ephemeral || tn.Node.Ephemeral, ControlURL: tn.ControlURL, APIBaseURL: tn.APIBaseURL,
			Role: "node", Authz: tn.Authz, DNSDisabled: dnsOff, Hostname: tn.Node.Hostname,
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (tn TailnetSpec) check(key string) error {
	if tn.Tailnet == "" {
		return fmt.Errorf("tailnet %q: tailnet is required (the tailnet name, for example example.ts.net, or \"-\" for the credential's own tailnet)", key)
	}
	if tn.Auth.ClientID == "" {
		return fmt.Errorf("tailnet %q: auth.client_id is required", key)
	}
	if err := tn.Auth.validate(); err != nil {
		return fmt.Errorf("tailnet %q: %w", key, err)
	}
	if tn.Auth.credentialCount() == 0 {
		return fmt.Errorf("tailnet %q: auth needs one of client_secret_file, client_secret_env, id_token_file or id_token_env", key)
	}
	if err := tn.Authz.validate(); err != nil {
		return fmt.Errorf("tailnet %q: %w", key, err)
	}
	if tn.Node.Hostname != "" && !shortNameRe.MatchString(tn.Node.Hostname) {
		return fmt.Errorf("tailnet %q: node.hostname %q must be 1 to 63 lowercase letters, digits or dashes, starting and ending with a letter or digit", key, tn.Node.Hostname)
	}
	return nil
}

func (t TargetSpec) check(key string, tailnets map[string]TailnetSpec) error {
	if t.In == "" {
		return fmt.Errorf("target %q: in is required", key)
	}
	if t.In != PodKey {
		if _, ok := tailnets[t.In]; !ok {
			return fmt.Errorf("target %q: in %q is not a tailnet key", key, t.In)
		}
	}
	kind := 0
	for _, set := range []bool{t.Tag != "", t.Device != "", t.Service != "", t.Addr != "", t.Host != ""} {
		if set {
			kind++
		}
	}
	switch {
	case kind == 0:
		return fmt.Errorf("target %q: needs one of tag, device, service, addr or host", key)
	case kind > 1:
		return fmt.Errorf("target %q: set only one of tag, device, service, addr or host", key)
	}
	if t.In == PodKey && t.Tag == "" && t.Device == "" && t.Service == "" {
		// addr or host, checked below
	} else if t.In == PodKey {
		return fmt.Errorf("target %q: a pod target sets addr or host", key)
	}
	if t.Service != "" && !strings.HasPrefix(t.Service, "svc:") {
		return fmt.Errorf("target %q: service %q must be a VIP name like svc:billing", key, t.Service)
	}
	if t.Addr != "" {
		if _, err := netip.ParseAddr(t.Addr); err != nil {
			return fmt.Errorf("target %q: addr %q must be an IP address", key, t.Addr)
		}
	}
	if t.Host != "" {
		if _, err := netip.ParseAddr(t.Host); err == nil {
			return fmt.Errorf("target %q: host %q is an IP address; set addr", key, t.Host)
		}
		if strings.ContainsAny(t.Host, " \t:/") {
			return fmt.Errorf("target %q: host %q must be a DNS name with no port", key, t.Host)
		}
	}
	if _, err := t.Ports.validated(); err != nil {
		return fmt.Errorf("target %q: %w", key, err)
	}
	return nil
}

func (f *File) exportRule(i int, ex ExportSpec) (BridgeRule, error) {
	where := fmt.Sprintf("exports[%d]", i)
	if ex.Target == "" {
		return BridgeRule{}, fmt.Errorf("%s: target is required", where)
	}
	tgt, ok := f.Targets[ex.Target]
	if !ok {
		return BridgeRule{}, fmt.Errorf("%s: target %q is not defined", where, ex.Target)
	}
	if err := ex.Authz.validate(); err != nil {
		return BridgeRule{}, fmt.Errorf("%s: %w", where, err)
	}
	if len(ex.To) == 0 {
		return BridgeRule{}, fmt.Errorf("%s: to is required", where)
	}
	seen := map[string]bool{}
	for _, to := range ex.To {
		if to == tgt.In {
			return BridgeRule{}, fmt.Errorf("%s: to includes %q, which is the target's in", where, to)
		}
		if _, ok := f.Tailnets[to]; !ok {
			return BridgeRule{}, fmt.Errorf("%s: to %q is not a tailnet key", where, to)
		}
		if seen[to] {
			return BridgeRule{}, fmt.Errorf("%s: to %q is duplicated", where, to)
		}
		seen[to] = true
	}
	name := ex.Name
	if name == "" {
		name = ex.Target
	}
	if !shortNameRe.MatchString(name) {
		return BridgeRule{}, fmt.Errorf("%s: name %q must be 1 to 63 lowercase letters, digits or dashes, starting and ending with a letter or digit", where, name)
	}
	if tgt.Tag != "" && ex.DNSName != "" && !strings.Contains(ex.DNSName, "{host}") {
		return BridgeRule{}, fmt.Errorf("%s: dns_name on a tag target must contain {host}", where)
	}
	if tgt.Tag == "" && strings.Contains(ex.DNSName, "{host}") {
		return BridgeRule{}, fmt.Errorf("%s: {host} is only for a tag target", where)
	}
	forwards, err := tgt.Ports.validated()
	if err != nil {
		return BridgeRule{}, fmt.Errorf("target %q: %w", ex.Target, err)
	}
	ports := make([]int, len(forwards))
	for i, fw := range forwards {
		ports[i] = fw.Expose
	}
	rule := BridgeRule{
		Name: ex.Target + "/" + name, Target: ex.Target, ExportName: name,
		DestTailnets: append([]string(nil), ex.To...),
		Authz:        ex.Authz.Effective(f.Authz),
		Ports:        ports, Forwards: forwards,
		DNSName: ex.DNSName, DNSZone: ex.DNSZone,
	}
	if tgt.Tag != "" {
		rule.Multi = true
		rule.SourceTailnet = tgt.In
		rule.From = tgt.In
		rule.SourceTag = tgt.Tag
		if err := checkDNSZone(expandHost(ex.DNSName, "host"), ex.DNSZone, where); err != nil {
			return BridgeRule{}, err
		}
		return rule, nil
	}
	if tgt.Device != "" || tgt.Service != "" {
		rule.SourceTailnet = tgt.In
		rule.From = tgt.In
		if tgt.Device != "" {
			rule.SourceDevices = []DeviceSpec{{FQDN: tgt.Device, DNSName: ex.DNSName, DNSZone: ex.DNSZone, ShortName: name}}
		} else {
			rule.SourceServices = []ServiceSpec{{Name: tgt.Service, DNSName: ex.DNSName, DNSZone: ex.DNSZone, ShortName: name}}
		}
		return rule, nil
	}
	dnsName := ex.DNSName
	if dnsName == "" && tgt.Host != "" {
		dnsName = tgt.Host
	}
	if dnsName == "" {
		return BridgeRule{}, fmt.Errorf("%s: dns_name is required for an addr target", where)
	}
	addr := tgt.Addr
	if tgt.Host != "" {
		addr = tgt.Host
	}
	src := LocalSourceSpec{
		Addr: addr, Ports: tgt.Ports, DNSName: dnsName, DNSZone: ex.DNSZone, ShortName: name,
	}
	if tgt.In != PodKey {
		src.Via = ViaTailnet
		rule.SourceTailnet = tgt.In
		rule.From = tgt.In
	}
	rule.LocalSources = []LocalSourceSpec{src}
	rule.Ports = nil
	return rule, nil
}

// expandHost replaces {host} so a tag template can be checked as a DNS name.
func expandHost(template, host string) string {
	if template == "" {
		return ""
	}
	return strings.ReplaceAll(template, "{host}", host)
}
