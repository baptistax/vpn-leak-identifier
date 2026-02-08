// File: internal/cli/cli.go (complete file)

package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/baptistax/vpn-leak-identifier/internal/app"
	"github.com/baptistax/vpn-leak-identifier/internal/logging"
	"github.com/baptistax/vpn-leak-identifier/internal/monitor"
	"github.com/baptistax/vpn-leak-identifier/internal/report"
	"github.com/baptistax/vpn-leak-identifier/internal/runctx"
	"github.com/baptistax/vpn-leak-identifier/internal/version"
)

const defaultExportsDir = "exports"

func Run(args []string) int {
	if len(args) == 0 {
		// Default flow: 30s test with kill-switch validation.
		args = []string{"test"}
	}

	switch args[0] {
	case "test":
		return runTest(args[1:])
	case "snapshot":
		return runSnapshot(args[1:])
	case "monitor":
		return runMonitor(args[1:])
	case "version":
		fmt.Printf("vpnleakidentifier %s (commit=%s build_date=%s)\n", version.Version, version.Commit, version.BuildDate)
		return 0
	case "help", "-h", "--help":
		printHelp()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", args[0])
		printHelp()
		return 2
	}
}

func printHelp() {
	fmt.Println(`vpnleakidentifier

Usage:
  vpnleakidentifier [test] [flags]
  vpnleakidentifier snapshot [flags]
  vpnleakidentifier monitor  [flags]
  vpnleakidentifier version

Default command:
  test   Runs for 30s and attempts to validate kill-switch behavior (detects exit IP changes or loss of connectivity)

Commands:
  test      Run a timed VPN + kill-switch validation (default)
  snapshot  Run one leak snapshot and write outputs to ./exports/run_<id>/
  monitor   Re-run snapshot every interval and print an event when changes occur

Examples:
  vpnleakidentifier
  vpnleakidentifier test
  vpnleakidentifier test -nks
  vpnleakidentifier snapshot --format text
  vpnleakidentifier monitor --interval 5s --format text
`)
}

type commonFlags struct {
	LogLevel string
	Format   string // json|text
	Exports  string
	Timeout  time.Duration

	EnableDNSLeakTest bool
	EnableSTUN        bool
	DNSQueries        int
	STUNServers       string
}

func bindCommon(fs *flag.FlagSet) *commonFlags {
	c := &commonFlags{}

	fs.StringVar(&c.LogLevel, "log-level", "info", "Log level: debug|info|warn|error")
	fs.StringVar(&c.Format, "format", "text", "Output format: json|text")
	fs.StringVar(&c.Exports, "exports", defaultExportsDir, "Base exports directory")
	fs.DurationVar(&c.Timeout, "timeout", 60*time.Second, "Overall CLI timeout")

	// Snapshot/monitor-specific toggles (kept for parity with the original skeleton).
	fs.BoolVar(&c.EnableDNSLeakTest, "dnsleaktest", false, "Enable dnsleaktest.com flow (snapshot/monitor)")
	fs.BoolVar(&c.EnableSTUN, "stun", true, "Enable STUN observed IP checks")
	fs.IntVar(&c.DNSQueries, "dns-queries", 6, "DNS queries for dnsleaktest.com flow")
	fs.StringVar(&c.STUNServers, "stun-servers", "", "Comma-separated STUN servers (host:port)")

	return c
}

func runTest(args []string) int {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	c := bindCommon(fs)

	var nks bool
	fs.BoolVar(&nks, "nks", false, "No kill-switch validation (5s VPN test only)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	logging.Setup(c.LogLevel)

	rc, err := runctx.New(c.Exports)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to create run directory:", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()

	// Allow Ctrl+C to stop the run.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		cancel()
	}()

	opt := app.TestOptions{
		Mode:        report.RunModeKillSwitch,
		Duration:    30 * time.Second,
		Baseline:    5 * time.Second,
		Interval:    1 * time.Second,
		EnableSTUN:  c.EnableSTUN,
		StunServers: splitCSV(c.STUNServers),
	}
	if nks {
		opt.Mode = report.RunModeVPNOnly
		opt.Duration = 5 * time.Second
	}

	rep := app.RunTest(ctx, opt)
	rep.RunID = rc.RunID
	rep.StartedUTC = rc.StartedAtUTC

	outJSON := filepath.Join(rc.OutputDir, "run.json")
	outTXT := filepath.Join(rc.OutputDir, "run.txt")

	_ = report.WriteRunJSON(outJSON, rep)
	_ = report.WriteRunText(outTXT, rep)

	if strings.ToLower(c.Format) == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return 0
	}

	fmt.Print(report.RenderRunText(rep))
	fmt.Printf("\nOutputs written to: %s\n", rc.OutputDir)
	return 0
}

func runSnapshot(args []string) int {
	fs := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	c := bindCommon(fs)

	if err := fs.Parse(args); err != nil {
		return 2
	}

	logging.Setup(c.LogLevel)

	rc, err := runctx.New(c.Exports)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to create run directory:", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()

	opt := app.SnapshotOptions{
		EnableDNSLeakTest: c.EnableDNSLeakTest,
		EnableSTUN:        c.EnableSTUN,
		DNSQueries:        c.DNSQueries,
		StunServers:       splitCSV(c.STUNServers),
	}

	s := app.TakeSnapshot(ctx, opt)

	outJSON := filepath.Join(rc.OutputDir, "snapshot.json")
	outTXT := filepath.Join(rc.OutputDir, "snapshot.txt")

	_ = report.WriteJSON(outJSON, s)
	_ = report.WriteText(outTXT, s)

	if strings.ToLower(c.Format) == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(s)
		return 0
	}

	_ = report.WriteText(filepath.Join(rc.OutputDir, "stdout.txt"), s)
	fmt.Printf("Outputs written to: %s\n", rc.OutputDir)
	return 0
}

func runMonitor(args []string) int {
	fs := flag.NewFlagSet("monitor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	c := bindCommon(fs)

	var interval time.Duration
	fs.DurationVar(&interval, "interval", 5*time.Second, "Snapshot interval (e.g. 5s)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	logging.Setup(c.LogLevel)

	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		cancel()
	}()

	opt := monitor.Options{
		Interval: interval,
		Timeout:  20 * time.Second,
		Snapshot: app.SnapshotOptions{
			EnableDNSLeakTest: c.EnableDNSLeakTest,
			EnableSTUN:        c.EnableSTUN,
			DNSQueries:        c.DNSQueries,
			StunServers:       splitCSV(c.STUNServers),
		},
	}

	format := strings.ToLower(c.Format)
	monitor.Run(ctx, opt, func(ev monitor.Event) {
		if format == "json" {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(ev)
			return
		}

		fmt.Printf("[%s] %s\n", ev.AtUTC.Format("2006-01-02T15:04:05Z"), ev.Message)
		if ev.Previous != nil && ev.Current != nil {
			printSnapshotDeltaText(*ev.Previous, *ev.Current)
		}
		fmt.Println()
	})

	return 0
}

func printSnapshotDeltaText(prev, cur report.Snapshot) {
	prevV4 := findPublicIP(prev.PublicIPs, "ipv4")
	curV4 := findPublicIP(cur.PublicIPs, "ipv4")
	if prevV4 != "" || curV4 != "" {
		if prevV4 != curV4 {
			fmt.Printf("  Exit IPv4: %s -> %s\n", printableIP(prevV4), printableIP(curV4))
		} else {
			fmt.Printf("  Exit IPv4: %s\n", printableIP(curV4))
		}
	}

	prevV6 := findPublicIP(prev.PublicIPs, "ipv6")
	curV6 := findPublicIP(cur.PublicIPs, "ipv6")
	if prevV6 != "" || curV6 != "" {
		if prevV6 != curV6 {
			fmt.Printf("  Exit IPv6: %s -> %s\n", printableIP(prevV6), printableIP(curV6))
		} else {
			fmt.Printf("  Exit IPv6: %s\n", printableIP(curV6))
		}
	}

	if !equalStringSets(prev.DnsRecursors, cur.DnsRecursors) {
		fmt.Printf("  DNS recursors: %s -> %s\n", strings.Join(prev.DnsRecursors, ", "), strings.Join(cur.DnsRecursors, ", "))
	}

	if !equalStringSets(prev.StunObserved, cur.StunObserved) {
		fmt.Printf("  STUN observed: %s -> %s\n", strings.Join(prev.StunObserved, ", "), strings.Join(cur.StunObserved, ", "))
	}
}

func findPublicIP(list []report.PublicIPResult, family string) string {
	for _, r := range list {
		if r.Family != family {
			continue
		}
		if r.Error != "" {
			return ""
		}
		return r.IP
	}
	return ""
}

func printableIP(ip string) string {
	if strings.TrimSpace(ip) == "" {
		return "(none)"
	}
	return ip
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ma := map[string]int{}
	for _, s := range a {
		ma[s]++
	}
	for _, s := range b {
		ma[s]--
		if ma[s] < 0 {
			return false
		}
	}
	for _, v := range ma {
		if v != 0 {
			return false
		}
	}
	return true
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}
