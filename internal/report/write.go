// File: internal/report/write.go (complete file)

package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func WriteJSON(path string, s Snapshot) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

func WriteText(path string, s Snapshot) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	var b strings.Builder
	b.WriteString("Timestamp (UTC): " + s.TimestampUTC.Format("2006-01-02T15:04:05Z") + "\n")

	for _, r := range s.PublicIPs {
		if r.Error != "" {
			b.WriteString(fmt.Sprintf("Public IP [%s/%s]: error: %s\n", r.Source, r.Family, r.Error))
			continue
		}
		b.WriteString(fmt.Sprintf("Public IP [%s/%s]: %s\n", r.Source, r.Family, r.IP))
	}

	if len(s.DnsRecursors) > 0 {
		b.WriteString("DNS recursors (via ns.ident.me): " + strings.Join(s.DnsRecursors, ", ") + "\n")
	}

	if len(s.DnsLeak) > 0 {
		b.WriteString("dnsleaktest.com observed recursors:\n")
		for _, d := range s.DnsLeak {
			b.WriteString(fmt.Sprintf("  %s (%s) - %s - %s, %s\n", d.IPAddress, d.Hostname, d.ISP, d.City, d.Country))
		}
	}

	if len(s.StunObserved) > 0 {
		b.WriteString("STUN observed public IPs: " + strings.Join(s.StunObserved, ", ") + "\n")
	}

	for _, n := range s.Notes {
		b.WriteString("Note: " + n + "\n")
	}

	return os.WriteFile(path, []byte(b.String()), 0o644)
}
