package state_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/user/portwatch/internal/state"
	"github.com/user/portwatch/internal/scanner"
)

// newTestScanner returns a minimal PortInfo slice for testing state logic.
func samplePorts() []scanner.PortInfo {
	return []scanner.PortInfo{
		{Protocol: "tcp", LocalAddress: "0.0.0.0", LocalPort: 80, State: "LISTEN", PID: 1234},
		{Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: 443, State: "LISTEN", PID: 5678},
	}
}

func TestNew_EmptyStateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s, err := state.New(path)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil state")
	}
}

func TestNew_InvalidPath(t *testing.T) {
	// Use a path inside a non-existent nested directory structure that cannot be created.
	_, err := state.New("/proc/nonexistent_portwatch_dir/state.json")
	if err == nil {
		t.Fatal("expected error for unwritable path, got nil")
	}
}

func TestDiff_NewPorts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s, err := state.New(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ports := samplePorts()
	added, removed := s.Diff(ports)

	// First run: all ports should appear as added.
	if len(added) != len(ports) {
		t.Errorf("expected %d added ports, got %d", len(ports), len(added))
	}
	if len(removed) != 0 {
		t.Errorf("expected 0 removed ports, got %d", len(removed))
	}
}

func TestDiff_RemovedPorts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s, err := state.New(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ports := samplePorts()

	// Commit initial state.
	s.Diff(ports)
	if err := s.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Remove one port and diff again.
	reduced := ports[:1]
	added, removed := s.Diff(reduced)

	if len(added) != 0 {
		t.Errorf("expected 0 added ports, got %d", len(added))
	}
	if len(removed) != 1 {
		t.Errorf("expected 1 removed port, got %d", len(removed))
	}
}

func TestDiff_AddedPort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s, err := state.New(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ports := samplePorts()

	// Commit initial state with only the first port.
	s.Diff(ports[:1])
	if err := s.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Now diff with both ports — second one is new.
	added, removed := s.Diff(ports)

	if len(added) != 1 {
		t.Errorf("expected 1 added port, got %d", len(added))
	}
	if len(removed) != 0 {
		t.Errorf("expected 0 removed ports, got %d", len(removed))
	}
}

func TestSaveAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s, err := state.New(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ports := samplePorts()
	s.Diff(ports)
	if err := s.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Reload state from disk.
	s2, err := state.New(path)
	if err != nil {
		t.Fatalf("reload error: %v", err)
	}

	// No changes expected after reload with same ports.
	added, removed := s2.Diff(ports)
	if len(added) != 0 || len(removed) != 0 {
		t.Errorf("expected no diff after reload, got added=%d removed=%d", len(added), len(removed))
	}
}

func TestSave_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s, err := state.New(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s.Diff(samplePorts())
	if err := s.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("expected state file to exist after Save")
	}
}
