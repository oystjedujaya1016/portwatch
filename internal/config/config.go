// Package config handles loading and validation of portwatch configuration.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// DefaultInterval is the default port scan interval.
const DefaultInterval = 30 * time.Second

// DefaultConfigPath is the default path to the configuration file.
const DefaultConfigPath = "/etc/portwatch/config.json"

// Config holds the runtime configuration for portwatch.
type Config struct {
	// Interval is how often the port scanner runs.
	Interval time.Duration `json:"interval"`

	// AllowedPorts is the explicit list of ports expected to be open.
	// If non-empty, any port not in this list will trigger an alert.
	AllowedPorts []uint16 `json:"allowed_ports"`

	// IgnoredPorts are ports to silently skip during alerting.
	IgnoredPorts []uint16 `json:"ignored_ports"`

	// AlertCommand is an optional shell command executed when a change is
	// detected. The string may contain {port} and {event} placeholders.
	AlertCommand string `json:"alert_command"`

	// Quiet suppresses informational output; only alerts are printed.
	Quiet bool `json:"quiet"`

	// LogFile is an optional path to write alert output. Defaults to stdout.
	LogFile string `json:"log_file"`
}

// rawConfig mirrors Config but uses a plain string for Interval so we can
// parse human-readable durations from JSON (e.g. "30s", "1m").
type rawConfig struct {
	Interval     string   `json:"interval"`
	AllowedPorts []uint16 `json:"allowed_ports"`
	IgnoredPorts []uint16 `json:"ignored_ports"`
	AlertCommand string   `json:"alert_command"`
	Quiet        bool     `json:"quiet"`
	LogFile      string   `json:"log_file"`
}

// Load reads a JSON configuration file from path and returns a validated Config.
// If path is empty, a default Config is returned.
func Load(path string) (*Config, error) {
	if path == "" {
		return defaults(), nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: open %q: %w", path, err)
	}
	defer f.Close()

	var raw rawConfig
	if err := json.NewDecoder(f).Decode(&raw); err != nil {
		return nil, fmt.Errorf("config: decode %q: %w", path, err)
	}

	cfg := &Config{
		AllowedPorts: raw.AllowedPorts,
		IgnoredPorts: raw.IgnoredPorts,
		AlertCommand: raw.AlertCommand,
		Quiet:        raw.Quiet,
		LogFile:      raw.LogFile,
	}

	if raw.Interval != "" {
		d, err := time.ParseDuration(raw.Interval)
		if err != nil {
			return nil, fmt.Errorf("config: invalid interval %q: %w", raw.Interval, err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("config: interval must be positive, got %q", raw.Interval)
		}
		cfg.Interval = d
	} else {
		cfg.Interval = DefaultInterval
	}

	return cfg, nil
}

// IsAllowed reports whether port should be considered expected.
// If AllowedPorts is empty every port is implicitly allowed.
func (c *Config) IsAllowed(port uint16) bool {
	if len(c.AllowedPorts) == 0 {
		return true
	}
	for _, p := range c.AllowedPorts {
		if p == port {
			return true
		}
	}
	return false
}

// IsIgnored reports whether port should be silently skipped.
func (c *Config) IsIgnored(port uint16) bool {
	for _, p := range c.IgnoredPorts {
		if p == port {
			return true
		}
	}
	return false
}

// defaults returns a Config populated with sensible defaults.
func defaults() *Config {
	return &Config{
		Interval: DefaultInterval,
	}
}
