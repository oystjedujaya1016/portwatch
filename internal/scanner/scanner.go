// Package scanner provides functionality to scan and detect open ports
// on the local system using /proc/net or system calls.
package scanner

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Port represents an open port with its associated metadata.
type Port struct {
	Protocol string
	LocalAddr string
	LocalPort int
	State     string
	PID       int
	Process   string
}

// String returns a human-readable representation of the port.
func (p Port) String() string {
	if p.Process != "" {
		return fmt.Sprintf("%s:%d (%s) [%s, pid=%d]", p.LocalAddr, p.LocalPort, p.Protocol, p.Process, p.PID)
	}
	return fmt.Sprintf("%s:%d (%s)", p.LocalAddr, p.LocalPort, p.Protocol)
}

// Scanner scans the local system for open ports.
type Scanner struct {
	// IncludeIPv6 controls whether IPv6 ports are included in results.
	IncludeIPv6 bool
}

// New creates a new Scanner with default settings.
func New() *Scanner {
	return &Scanner{
		IncludeIPv6: true,
	}
}

// Scan returns all currently open ports on the system.
func (s *Scanner) Scan() ([]Port, error) {
	var ports []Port

	tcpPorts, err := s.readProcNet("/proc/net/tcp", "tcp")
	if err != nil {
		return nil, fmt.Errorf("scanning tcp ports: %w", err)
	}
	ports = append(ports, tcpPorts...)

	udpPorts, err := s.readProcNet("/proc/net/udp", "udp")
	if err != nil {
		return nil, fmt.Errorf("scanning udp ports: %w", err)
	}
	ports = append(ports, udpPorts...)

	if s.IncludeIPv6 {
		tcp6Ports, err := s.readProcNet("/proc/net/tcp6", "tcp6")
		if err == nil {
			ports = append(ports, tcp6Ports...)
		}

		udp6Ports, err := s.readProcNet("/proc/net/udp6", "udp6")
		if err == nil {
			ports = append(ports, udp6Ports...)
		}
	}

	return ports, nil
}

// readProcNet parses a /proc/net file and extracts listening ports.
// Only entries in LISTEN state (0A) for TCP or unconditional for UDP are included.
func (s *Scanner) readProcNet(path, protocol string) ([]Port, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var ports []Port
	scanner := bufio.NewScanner(f)

	// Skip header line
	scanner.Scan()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		state := fields[3]
		// For TCP, only include LISTEN state (0A); for UDP include all (no state)
		if strings.HasPrefix(protocol, "tcp") && state != "0A" {
			continue
		}

		addr, port, err := parseHexAddr(fields[1])
		if err != nil {
			continue
		}

		ports = append(ports, Port{
			Protocol:  protocol,
			LocalAddr: addr,
			LocalPort: port,
			State:     stateToString(state),
		})
	}

	return ports, scanner.Err()
}

// parseHexAddr parses a hex-encoded address:port pair from /proc/net files.
// Format is: AABBCCDD:PPPP (little-endian hex IP and port).
func parseHexAddr(hexAddr string) (string, int, error) {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid address format: %s", hexAddr)
	}

	portVal, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port: %s", parts[1])
	}

	// IPv4: 8 hex chars; IPv6: 32 hex chars
	var ipStr string
	if len(parts[0]) == 8 {
		ipBytes := make([]byte, 4)
		val, err := strconv.ParseUint(parts[0], 16, 32)
		if err != nil {
			return "", 0, err
		}
		// little-endian byte order
		ipBytes[0] = byte(val)
		ipBytes[1] = byte(val >> 8)
		ipBytes[2] = byte(val >> 16)
		ipBytes[3] = byte(val >> 24)
		ipStr = net.IP(ipBytes).String()
	} else {
		ipStr = parts[0]
	}

	return ipStr, int(portVal), nil
}

// stateToString converts a hex TCP state code to a readable string.
func stateToString(hexState string) string {
	states := map[string]string{
		"01": "ESTABLISHED",
		"02": "SYN_SENT",
		"03": "SYN_RECV",
		"04": "FIN_WAIT1",
		"05": "FIN_WAIT2",
		"06": "TIME_WAIT",
		"07": "CLOSE",
		"08": "CLOSE_WAIT",
		"09": "LAST_ACK",
		"0A": "LISTEN",
		"0B": "CLOSING",
	}
	if s, ok := states[strings.ToUpper(hexState)]; ok {
		return s
	}
	return hexState
}
