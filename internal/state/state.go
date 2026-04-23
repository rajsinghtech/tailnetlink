package state

import (
	"fmt"
	"sync"
	"time"
)

// Store holds live bridge state and broadcasts SSE events to HTTP subscribers.
type Store struct {
	mu          sync.RWMutex
	tailnets    map[string]*TailnetStatus
	bridges     map[string]*BridgeEntry
	connections map[string]*ConnEntry
	closedConns []*ConnEntry // ring buffer of recently-closed, max 200
	logs        []LogEntry
	startTime   time.Time

	subMu       sync.Mutex
	subscribers map[chan Event]struct{}
}

func New() *Store {
	return &Store{
		tailnets:    make(map[string]*TailnetStatus),
		bridges:     make(map[string]*BridgeEntry),
		connections: make(map[string]*ConnEntry),
		closedConns: make([]*ConnEntry, 0, 200),
		startTime:   time.Now(),
		subscribers: make(map[chan Event]struct{}),
	}
}

// --- Domain types ---

type TailnetStatus struct {
	Name      string   `json:"name"`
	Role      string   `json:"role"` // "source" | "dest"
	Connected bool     `json:"connected"`
	Devices   []Device `json:"devices"`
	Tag       string   `json:"tag"`
}

type Device struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
}

type BridgeEntry struct {
	ID          string    `json:"id"`
	RuleName    string    `json:"rule_name"`
	DestTailnet string    `json:"dest_tailnet"`
	ServiceName string    `json:"service_name"`
	SourceHost  string    `json:"source_host"`
	SourceIP    string    `json:"source_ip"`
	DestVIP     string    `json:"dest_vip"`
	Ports       []int     `json:"ports"`
	Status      string    `json:"status"` // "active" | "pending" | "error"
	Error       string    `json:"error,omitempty"`
	ConnCount   int       `json:"conn_count"`
	BytesIn     int64     `json:"bytes_in"`
	BytesOut    int64     `json:"bytes_out"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ConnEntry struct {
	ID          string     `json:"id"`
	BridgeID    string     `json:"bridge_id"`
	ServiceName string     `json:"service_name"`
	ClientAddr  string     `json:"client_addr"`
	NodeName    string     `json:"node_name,omitempty"` // short Tailscale hostname
	Identity    string     `json:"identity,omitempty"`  // email (user) or tag:xxx (service)
	TargetAddr  string     `json:"target_addr"`
	BytesIn     int64      `json:"bytes_in"`
	BytesOut    int64      `json:"bytes_out"`
	OpenedAt    time.Time  `json:"opened_at"`
	ClosedAt    *time.Time `json:"closed_at,omitempty"`
}

type LogEntry struct {
	Time    time.Time         `json:"time"`
	Level   string            `json:"level"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"`
}

type StatusSnapshot struct {
	Uptime      string           `json:"uptime"`
	Tailnets    []*TailnetStatus `json:"tailnets"`
	BridgeCount int              `json:"bridge_count"`
	ConnCount   int              `json:"conn_count"`
	BytesTotal  int64            `json:"bytes_total"`
	StartTime   time.Time        `json:"start_time"`
}

// --- SSE events ---

type Event struct {
	Type    string `json:"type"`
	Payload any    `json:"payload"`
}

const (
	EventInit           = "init"
	EventTailnetUpdated = "tailnet_updated"
	EventBridgeCreated  = "bridge_created"
	EventBridgeUpdated  = "bridge_updated"
	EventBridgeDeleted  = "bridge_deleted"
	EventConnOpened     = "conn_opened"
	EventConnClosed     = "conn_closed"
	EventLog            = "log"
)

const (
	BridgeStatusPending = "pending"
	BridgeStatusActive  = "active"
	BridgeStatusError   = "error"
)

// --- Tailnet methods ---

func (s *Store) SetTailnet(id string, status TailnetStatus) {
	s.mu.Lock()
	s.tailnets[id] = &status
	s.mu.Unlock()
	s.broadcast(Event{Type: EventTailnetUpdated, Payload: status})
}

func (s *Store) DeleteTailnet(id string) {
	s.mu.Lock()
	delete(s.tailnets, id)
	s.mu.Unlock()
	s.broadcast(Event{Type: EventTailnetUpdated, Payload: nil})
}

// --- Bridge methods ---

func (s *Store) UpsertBridge(b BridgeEntry) {
	b.UpdatedAt = time.Now()
	s.mu.Lock()
	_, exists := s.bridges[b.ID]
	s.bridges[b.ID] = &b
	s.mu.Unlock()
	evType := EventBridgeUpdated
	if !exists {
		evType = EventBridgeCreated
	}
	s.broadcast(Event{Type: evType, Payload: b})
}

func (s *Store) DeleteBridge(id string) {
	s.mu.Lock()
	delete(s.bridges, id)
	s.mu.Unlock()
	s.broadcast(Event{Type: EventBridgeDeleted, Payload: id})
}

func (s *Store) IncrBridgeConn(bridgeID string, delta int) {
	var entry BridgeEntry
	var found bool
	s.mu.Lock()
	if b, ok := s.bridges[bridgeID]; ok {
		b.ConnCount += delta
		entry = *b
		found = true
	}
	s.mu.Unlock()
	if found {
		s.broadcast(Event{Type: EventBridgeUpdated, Payload: entry})
	}
}

func (s *Store) AddBridgeBytes(bridgeID string, in, out int64) {
	s.mu.Lock()
	if b, ok := s.bridges[bridgeID]; ok {
		b.BytesIn += in
		b.BytesOut += out
	}
	s.mu.Unlock()
}

// --- Connection methods ---

func (s *Store) OpenConn(c ConnEntry) {
	s.mu.Lock()
	s.connections[c.ID] = &c
	s.mu.Unlock()
	s.broadcast(Event{Type: EventConnOpened, Payload: c})
}

// CloseConn marks the connection closed and moves it to the recent-closed ring
// buffer (max 200 entries). The SSE payload is the full ConnEntry with ClosedAt
// set so the UI can update bytes and duration in-place.
func (s *Store) CloseConn(id string, bytesIn, bytesOut int64) {
	s.mu.Lock()
	c, ok := s.connections[id]
	if ok {
		c.BytesIn = bytesIn
		c.BytesOut = bytesOut
		now := time.Now()
		c.ClosedAt = &now
		delete(s.connections, id)
		if len(s.closedConns) >= 200 {
			copy(s.closedConns, s.closedConns[1:])
			s.closedConns[len(s.closedConns)-1] = c
		} else {
			s.closedConns = append(s.closedConns, c)
		}
	}
	s.mu.Unlock()
	if ok {
		s.broadcast(Event{Type: EventConnClosed, Payload: *c})
	}
}

// --- Log methods ---

func (s *Store) Log(level, msg string, fields map[string]string) {
	entry := LogEntry{Time: time.Now(), Level: level, Message: msg, Fields: fields}
	s.mu.Lock()
	if len(s.logs) >= 500 {
		copy(s.logs, s.logs[1:])
		s.logs[len(s.logs)-1] = entry
	} else {
		s.logs = append(s.logs, entry)
	}
	s.mu.Unlock()
	s.broadcast(Event{Type: EventLog, Payload: entry})
}

// --- Read methods ---

func (s *Store) GetStatus() StatusSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var tailnets []*TailnetStatus
	for _, t := range s.tailnets {
		cp := *t
		tailnets = append(tailnets, &cp)
	}

	var bytesTotal int64
	for _, b := range s.bridges {
		bytesTotal += b.BytesIn + b.BytesOut
	}

	elapsed := time.Since(s.startTime)
	uptime := formatDuration(elapsed)

	return StatusSnapshot{
		Uptime:      uptime,
		Tailnets:    tailnets,
		BridgeCount: len(s.bridges),
		ConnCount:   len(s.connections),
		BytesTotal:  bytesTotal,
		StartTime:   s.startTime,
	}
}

func (s *Store) GetBridges() []*BridgeEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*BridgeEntry, 0, len(s.bridges))
	for _, b := range s.bridges {
		cp := *b
		out = append(out, &cp)
	}
	return out
}

// GetConns returns all currently-open connections plus recently-closed ones
// (within the last 5 minutes) from the ring buffer.
func (s *Store) GetConns() []*ConnEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cutoff := time.Now().Add(-5 * time.Minute)
	var out []*ConnEntry
	for _, c := range s.closedConns {
		if c.ClosedAt != nil && c.ClosedAt.After(cutoff) {
			cp := *c
			out = append(out, &cp)
		}
	}
	for _, c := range s.connections {
		cp := *c
		out = append(out, &cp)
	}
	return out
}

func (s *Store) GetLogs(n int) []LogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n <= 0 || n > len(s.logs) {
		n = len(s.logs)
	}
	out := make([]LogEntry, n)
	copy(out, s.logs[len(s.logs)-n:])
	return out
}

// --- Pub/sub ---

func (s *Store) Subscribe() chan Event {
	ch := make(chan Event, 64)
	s.subMu.Lock()
	s.subscribers[ch] = struct{}{}
	s.subMu.Unlock()
	return ch
}

func (s *Store) Unsubscribe(ch chan Event) {
	s.subMu.Lock()
	delete(s.subscribers, ch)
	s.subMu.Unlock()
	close(ch)
}

func (s *Store) broadcast(e Event) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	for ch := range s.subscribers {
		select {
		case ch <- e:
		default:
			// slow subscriber: drop
		}
	}
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	if h > 0 {
		return fmt.Sprintf("%dh %02dm", h, int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dm %02ds", int(d.Minutes()), int(d.Seconds())%60)
}
