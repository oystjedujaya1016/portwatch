package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yourusername/portwatch/internal/config"
)

func TestLoad_Defaults(t *testing.T) {
	// Load with a non-existent path to exercise defaults
	cfg, err := config.Load("/nonexistent/path/portwatch.toml")
	if err != nil {
		t.Fatalf("Load() with missing file should not error, got: %v", err)
	}

	if cfg.Interval <= 0 {
		t.Errorf("expected positive default interval, got %v", cfg.Interval)
	}

	if cfg.StateFile == "" {
		t.Error("expected non-empty default state file path")
	}
}

func TestLoad_FromFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "portwatch.toml")

	content := `
interval = "10s"
state_file = "/tmp/portwatch_test.state"
quiet = true

[alert]
  slack_webhook = "https://hooks.slack.com/test"

[scan]
  protocols = ["tcp", "udp"]
  exclude_ports = [22, 80]
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	if cfg.Interval != 10*time.Second {
		t.Errorf("expected interval 10s, got %v", cfg.Interval)
	}

	if cfg.StateFile != "/tmp/portwatch_test.state" {
		t.Errorf("expected state file /tmp/portwatch_test.state, got %q", cfg.StateFile)
	}

	if !cfg.Quiet {
		t.Error("expected quiet=true")
	}

	if cfg.Alert.SlackWebhook != "https://hooks.slack.com/test" {
		t.Errorf("unexpected slack webhook: %q", cfg.Alert.SlackWebhook)
	}

	if len(cfg.Scan.Protocols) != 2 {
		t.Errorf("expected 2 protocols, got %d", len(cfg.Scan.Protocols))
	}

	if len(cfg.Scan.ExcludePorts) != 2 {
		t.Errorf("expected 2 excluded ports, got %d", len(cfg.Scan.ExcludePorts))
	}
}

func TestLoad_InvalidTOML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.toml")

	if err := os.WriteFile(cfgPath, []byte("this is [not valid toml"), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	_, err := config.Load(cfgPath)
	if err == nil {
		t.Error("expected error for invalid TOML, got nil")
	}
}

func TestLoad_InvalidInterval(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "portwatch.toml")

	content := `interval = "not-a-duration"`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	_, err := config.Load(cfgPath)
	if err == nil {
		t.Error("expected error for invalid interval duration, got nil")
	}
}
