// Package alert provides notification mechanisms for port state changes.
package alert

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/user/portwatch/internal/scanner"
)

// EventType represents the kind of port change detected.
type EventType string

const (
	// EventOpened indicates a port that was not previously open is now open.
	EventOpened EventType = "OPENED"
	// EventClosed indicates a port that was previously open is now closed.
	EventClosed EventType = "CLOSED"
)

// Event describes a single port state change.
type Event struct {
	Type      EventType
	Port      scanner.PortInfo
	Timestamp time.Time
}

// Alerter handles formatting and dispatching of port change events.
type Alerter struct {
	out    io.Writer
	quiet  bool
	events []Event
}

// Option is a functional option for configuring an Alerter.
type Option func(*Alerter)

// WithWriter sets a custom output writer (defaults to os.Stdout).
func WithWriter(w io.Writer) Option {
	return func(a *Alerter) {
		a.out = w
	}
}

// WithQuiet suppresses informational output; only alerts are printed.
func WithQuiet(q bool) Option {
	return func(a *Alerter) {
		a.quiet = q
	}
}

// New creates a new Alerter with the provided options.
func New(opts ...Option) *Alerter {
	a := &Alerter{
		out: os.Stdout,
	}
	for _, o := range opts {
		o(a)
	}
	return a
}

// Diff compares a previous snapshot against the current one and emits events
// for any ports that have been opened or closed.
func (a *Alerter) Diff(prev, curr []scanner.PortInfo) []Event {
	prevMap := indexPorts(prev)
	currMap := indexPorts(curr)

	var events []Event
	now := time.Now()

	// Detect newly opened ports.
	for key, port := range currMap {
		if _, existed := prevMap[key]; !existed {
			events = append(events, Event{
				Type:      EventOpened,
				Port:      port,
				Timestamp: now,
			})
		}
	}

	// Detect newly closed ports.
	for key, port := range prevMap {
		if _, exists := currMap[key]; !exists {
			events = append(events, Event{
				Type:      EventClosed,
				Port:      port,
				Timestamp: now,
			})
		}
	}

	a.events = append(a.events, events...)
	return events
}

// Notify prints a human-readable alert for each event to the configured writer.
func (a *Alerter) Notify(events []Event) {
	for _, e := range events {
		var symbol string
		switch e.Type {
		case EventOpened:
			symbol = "[+]"
		case EventClosed:
			symbol = "[-]"
		}
		fmt.Fprintf(
			a.out,
			"%s %s PORT %s/%d (pid %d) %s\n",
			e.Timestamp.Format("15:04:05"),
			symbol,
			e.Port.Protocol,
			e.Port.Port,
			e.Port.PID,
			e.Port.State,
		)
	}
}

// History returns all events recorded since the Alerter was created.
func (a *Alerter) History() []Event {
	return a.events
}

// indexPorts builds a lookup map keyed by "protocol:port" for fast diffing.
func indexPorts(ports []scanner.PortInfo) map[string]scanner.PortInfo {
	m := make(map[string]scanner.PortInfo, len(ports))
	for _, p := range ports {
		key := fmt.Sprintf("%s:%d", p.Protocol, p.Port)
		m[key] = p
	}
	return m
}
