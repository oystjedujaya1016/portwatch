package scanner

import (
	"net"
	"testing"
)

// TestParseHexAddr verifies that hexadecimal address strings from /proc/net/tcp
// are correctly decoded into host:port strings.
func TestParseHexAddr(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantIP  string
		wantPort uint16
		wantErr bool
	}{
		{
			name:     "localhost port 80",
			input:    "0100007F:0050",
			wantIP:   "127.0.0.1",
			wantPort: 80,
			wantErr:  false,
		},
		{
			name:     "all interfaces port 8080",
			input:    "00000000:1F90",
			wantIP:   "0.0.0.0",
			wantPort: 8080,
			wantErr:  false,
		},
		{
			name:     "localhost port 22",
			input:    "0100007F:0016",
			wantIP:   "127.0.0.1",
			wantPort: 22,
			wantErr:  false,
		},
		{
			name:    "invalid format missing colon",
			input:   "0100007F0050",
			wantErr: true,
		},
		{
			name:    "invalid hex in address",
			input:   "GGGGGGGG:0050",
			wantErr: true,
		},
		{
			name:    "invalid hex in port",
			input:   "0100007F:ZZZZ",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, port, err := parseHexAddr(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseHexAddr(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseHexAddr(%q) unexpected error: %v", tt.input, err)
			}
			if ip.String() != tt.wantIP {
				t.Errorf("parseHexAddr(%q) IP = %v, want %v", tt.input, ip, tt.wantIP)
			}
			if port != tt.wantPort {
				t.Errorf("parseHexAddr(%q) port = %d, want %d", tt.input, port, tt.wantPort)
			}
		})
	}
}

// TestNew_InvalidProcPath ensures that New returns an error when given a
// non-existent proc filesystem path.
func TestNew_InvalidProcPath(t *testing.T) {
	_, err := New("/nonexistent/proc/path")
	if err == nil {
		t.Error("New with invalid proc path should return an error")
	}
}

// TestNew_DefaultPath verifies that New succeeds with the default /proc path
// on Linux systems where /proc/net/tcp is available.
func TestNew_DefaultPath(t *testing.T) {
	// This test only runs where /proc/net/tcp exists (Linux).
	const procTCP = "/proc/net/tcp"
	if !fileExists(procTCP) {
		t.Skipf("skipping: %s not available on this platform", procTCP)
	}

	s, err := New("/proc")
	if err != nil {
		t.Fatalf("New(\"/proc\") unexpected error: %v", err)
	}
	if s == nil {
		t.Fatal("New(\"/proc\") returned nil scanner")
	}

	ports, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() unexpected error: %v", err)
	}
	// We can't assert specific ports, but the result should be a valid slice.
	if ports == nil {
		t.Error("Scan() returned nil slice")
	}
	for _, p := range ports {
		if p.Port == 0 {
			t.Errorf("Scan() returned entry with port 0: %+v", p)
		}
		if net.ParseIP(p.IP) == nil {
			t.Errorf("Scan() returned entry with invalid IP %q", p.IP)
		}
	}
}

// fileExists is a helper that reports whether a file path exists.
func fileExists(path string) bool {
	_, err := openFile(path)
	return err == nil
}
