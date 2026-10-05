package tailnet

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Prefix starts the display name of every tailnet CI creates. Nothing that
// lacks it is ever deleted by the cleanup tooling.
const Prefix = "tailnetlink-ci-"

var nameRE = regexp.MustCompile(`^tailnetlink-ci-([0-9]+)-([0-9]+)-([a-z][a-z0-9]*)$`)

// Name returns the display name for one tailnet of one CI run attempt,
// for example tailnetlink-ci-123456-1-src.
func Name(runID, attempt, role string) string {
	return fmt.Sprintf("%s%s-%s-%s", Prefix, runID, attempt, role)
}

// ParseName splits a CI tailnet display name. ok is false for anything that
// isn't exactly a CI name, including the organization's own tailnet.
func ParseName(name string) (runID, attempt, role string, ok bool) {
	m := nameRE.FindStringSubmatch(name)
	if m == nil {
		return "", "", "", false
	}
	return m[1], m[2], m[3], true
}

// StateEntry records how to clean up one CI tailnet. It holds no secrets:
// the federated identity client ID and audience are public.
type StateEntry struct {
	RunID       string `json:"runId"`
	Attempt     string `json:"attempt"`
	Role        string `json:"role"`
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	DNSName     string `json:"dnsName,omitempty"`
	FedClientID string `json:"fedClientId,omitempty"`
	FedAudience string `json:"fedAudience,omitempty"`
}

// State is the JSON file the create step writes and uploads as an artifact.
type State struct {
	Tailnets []StateEntry `json:"tailnets"`
}

// Upsert adds e or replaces the entry with the same tailnet ID.
func (s *State) Upsert(e StateEntry) {
	for i := range s.Tailnets {
		if s.Tailnets[i].ID == e.ID {
			s.Tailnets[i] = e
			return
		}
	}
	s.Tailnets = append(s.Tailnets, e)
}

// Lookup returns the entry for tailnet id or display name.
func (s *State) Lookup(id, displayName string) (StateEntry, bool) {
	for _, e := range s.Tailnets {
		if (id != "" && e.ID == id) || (displayName != "" && e.DisplayName == displayName) {
			return e, true
		}
	}
	return StateEntry{}, false
}

// Save writes s to path atomically.
func (s *State) Save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadState reads one state file. A missing file is an empty state.
func LoadState(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &State{}, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &s, nil
}

// LoadStateDir merges every *.json state file under dir (for example a
// directory of downloaded run artifacts). A missing dir is an empty state.
func LoadStateDir(dir string) (*State, error) {
	merged := &State{}
	if dir == "" {
		return merged, nil
	}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		s, err := LoadState(p)
		if err != nil {
			return err
		}
		for _, e := range s.Tailnets {
			merged.Upsert(e)
		}
		return nil
	})
	return merged, err
}
