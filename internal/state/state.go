// Package state manages the persistent state of observed ports between scans.
// It tracks which ports were open during the last scan and computes diffs
// to detect newly opened or closed ports.
package state

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// PortEntry represents a single open port recorded in the state.
type PortEntry struct {
	Protocol string `json:"protocol"`
	LocalAddr string `json:"local_addr"`
	Port      uint16 `json:"port"`
	PID       int    `json:"pid,omitempty"`
	Process   string `json:"process,omitempty"`
}

// Key returns a unique string identifier for the port entry.
func (p PortEntry) Key() string {
	return p.Protocol + ":" + p.LocalAddr
}

// Snapshot holds the set of open ports observed at a point in time.
type Snapshot struct {
	Timestamp time.Time            `json:"timestamp"`
	Ports     map[string]PortEntry `json:"ports"` // keyed by PortEntry.Key()
}

// Diff describes changes between two snapshots.
type Diff struct {
	Opened []PortEntry
	Closed []PortEntry
}

// HasChanges returns true if there are any opened or closed ports.
func (d Diff) HasChanges() bool {
	return len(d.Opened) > 0 || len(d.Closed) > 0
}

// State manages the current and previous port snapshots.
type State struct {
	mu       sync.Mutex
	current  *Snapshot
	filePath string
}

// New creates a new State, optionally loading persisted state from filePath.
// If filePath is empty, state is kept in memory only.
func New(filePath string) (*State, error) {
	s := &State{filePath: filePath}
	if filePath != "" {
		if err := s.load(); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	return s, nil
}

// Update compares a new set of port entries against the current snapshot,
// returns a Diff, and advances the current snapshot.
func (s *State) Update(entries []PortEntry) (Diff, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	newPorts := make(map[string]PortEntry, len(entries))
	for _, e := range entries {
		newPorts[e.Key()] = e
	}

	var diff Diff

	if s.current != nil {
		// Find closed ports (present before, missing now).
		for key, entry := range s.current.Ports {
			if _, ok := newPorts[key]; !ok {
				diff.Closed = append(diff.Closed, entry)
			}
		}
		// Find opened ports (missing before, present now).
		for key, entry := range newPorts {
			if _, ok := s.current.Ports[key]; !ok {
				diff.Opened = append(diff.Opened, entry)
			}
		}
	}

	s.current = &Snapshot{
		Timestamp: time.Now(),
		Ports:     newPorts,
	}

	if s.filePath != "" {
		if err := s.persist(); err != nil {
			return diff, err
		}
	}

	return diff, nil
}

// Current returns a copy of the current snapshot, or nil if none exists yet.
func (s *State) Current() *Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil {
		return nil
	}
	copy := &Snapshot{
		Timestamp: s.current.Timestamp,
		Ports:     make(map[string]PortEntry, len(s.current.Ports)),
	}
	for k, v := range s.current.Ports {
		copy.Ports[k] = v
	}
	return copy
}

// load reads a persisted snapshot from disk.
func (s *State) load() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	s.current = &snap
	return nil
}

// persist writes the current snapshot to disk atomically.
func (s *State) persist() error {
	data, err := json.MarshalIndent(s.current, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.filePath)
}
