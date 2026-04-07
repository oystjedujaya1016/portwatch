package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/user/portwatch/monitor"
)

const (
	defaultInterval = 5 * time.Second
	version         = "0.1.0"
)

func main() {
	// CLI flags
	interval := flag.Duration("interval", defaultInterval, "Polling interval for port checks (e.g. 5s, 1m)")
	configFile := flag.String("config", "", "Path to config file (optional)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")

	flag.Parse()

	if *showVersion {
		fmt.Printf("portwatch v%s\n", version)
		os.Exit(0)
	}

	fmt.Printf("portwatch v%s starting...\n", version)
	fmt.Printf("Polling interval: %s\n", *interval)

	// Load configuration
	cfg, err := monitor.LoadConfig(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	if *verbose {
		cfg.Verbose = true
	}

	// Initialize the port monitor
	m := monitor.New(cfg)

	// Take an initial snapshot of open ports
	if err := m.Snapshot(); err != nil {
		fmt.Fprintf(os.Stderr, "Error taking initial port snapshot: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Initial port snapshot taken. Watching for changes...")

	// Set up graceful shutdown on SIGINT/SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.Check(); err != nil {
				fmt.Fprintf(os.Stderr, "Error during port check: %v\n", err)
			}
		case sig := <-sigCh:
			fmt.Printf("\nReceived signal %s, shutting down.\n", sig)
			return
		}
	}
}
