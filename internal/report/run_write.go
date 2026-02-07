// File: internal/report/run_write.go (complete file)

package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func WriteRunJSON(path string, r RunReport) error {
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
	return enc.Encode(r)
}

func WriteRunText(path string, r RunReport) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(RenderRunText(r)), 0o644)
}

func RenderRunText(r RunReport) string {
	var b strings.Builder

	writeBanner(&b)
	writeRunLine(&b, r)
	b.WriteString("\n")

	// Summary lines.
	writeExitLine(&b, "Exit IPv4", r.Baseline.ExitV4, findExitDelta(r, "ipv4"))
	writeExitLine(&b, "Exit IPv6", r.Baseline.ExitV6, findExitDelta(r, "ipv6"))
	writeDNSLine(&b, r)
	b.WriteString("\n")

	// Result.
	if r.Mode == RunModeKillSwitch {
		b.WriteString(fmt.Sprintf("Kill-switch: %s\n", r.Verdict.KillSwitch))
		if r.OfflineAtSec != nil {
			b.WriteString(fmt.Sprintf("Offline at: T+%ds\n", *r.OfflineAtSec))
		}
	} else {
		b.WriteString("VPN test: OK\n")
	}
	if strings.TrimSpace(r.Verdict.Reason) != "" {
		b.WriteString("Reason: " + strings.TrimSpace(r.Verdict.Reason) + "\n")
	}

	// Notes (kept short and de-duplicated).
	notes := []string{}
	notes = append(notes, r.Notes...)
	notes = append(notes, r.Baseline.Notes...)
	notes = append(notes, r.End.Notes...)
	if len(notes) > 0 {
		b.WriteString("\n")
		for _, n := range uniqStrings(notes) {
			b.WriteString("- " + n + "\n")
		}
	}

	return b.String()
}

func writeBanner(b *strings.Builder) {
	b.WriteString("========================\n")
	b.WriteString("      vpnleakID\n")
	b.WriteString("========================\n")
}

func writeRunLine(b *strings.Builder, r RunReport) {
	started := r.StartedUTC.Format("2006-01-02T15:04:05Z")
	if r.Mode == RunModeKillSwitch {
		b.WriteString(fmt.Sprintf("Run: %s  |  Duration: %s  |  Interval: %s\n", started, durShort(r.Duration), durShort(r.Interval)))
		return
	}
	b.WriteString(fmt.Sprintf("Run: %s  |  Duration: %s\n", started, durShort(r.Duration)))
}

func durShort(d time.Duration) string {
	// Keep the printed form stable (e.g. 30s, 1s).
	if d%time.Second == 0 {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return d.String()
}

func writeExitLine(b *strings.Builder, label string, base ExitInfo, d *ExitDelta) {
	if base.Error != "" {
		switch strings.ToLower(strings.TrimSpace(base.Error)) {
		case "disabled":
			b.WriteString(fmt.Sprintf("%s: disabled\n", label))
		default:
			b.WriteString(fmt.Sprintf("%s: unavailable\n", label))
		}
		return
	}
	if strings.TrimSpace(base.IP) == "" {
		b.WriteString(fmt.Sprintf("%s: unavailable\n", label))
		return
	}

	if d == nil || strings.TrimSpace(d.To.IP) == "" {
		b.WriteString(fmt.Sprintf("%s: %s%s\n", label, base.IP, formatGeoSuffix(base.Geo)))
		return
	}

	b.WriteString(fmt.Sprintf("%s: %s%s  ->  %s%s  [T+%ds]\n",
		label,
		d.From.IP,
		formatGeoSuffix(d.From.Geo),
		d.To.IP,
		formatGeoSuffix(d.To.Geo),
		d.AtSec,
	))
}

func writeDNSLine(b *strings.Builder, r RunReport) {
	base := formatDNSShort(r.Baseline.DNSRecursors)
	if base == "" {
		return
	}
	if r.DNSDelta == nil {
		b.WriteString(fmt.Sprintf("DNS: %s\n", base))
		return
	}
	from := formatDNSShort(r.DNSDelta.From)
	to := formatDNSShort(r.DNSDelta.To)
	if from == "" {
		from = base
	}
	b.WriteString(fmt.Sprintf("DNS: %s  ->  %s  [T+%ds]\n", from, to, r.DNSDelta.AtSec))
}

func formatDNSShort(list []string) string {
	if len(list) == 0 {
		return ""
	}
	var v4 string
	hasV6 := false
	for _, s := range list {
		ip := strings.TrimSpace(s)
		if ip == "" {
			continue
		}
		if strings.Contains(ip, ":") {
			hasV6 = true
			continue
		}
		if v4 == "" {
			v4 = ip
		}
	}

	if v4 == "" {
		if hasV6 {
			return "ipv6"
		}
		return ""
	}
	if hasV6 {
		return v4 + ", ipv6"
	}
	return v4
}

func formatGeoSuffix(g GeoInfo) string {
	loc := formatLocation(g)
	if loc == "" {
		return ""
	}
	return " (" + loc + ")"
}

func formatLocation(g GeoInfo) string {
	parts := []string{}
	cc := strings.TrimSpace(g.CountryCode)
	if cc != "" {
		parts = append(parts, cc)
	} else if country := strings.TrimSpace(g.Country); country != "" {
		parts = append(parts, country)
	}

	if city := strings.TrimSpace(g.City); city != "" {
		parts = append(parts, city)
	} else if region := strings.TrimSpace(g.Region); region != "" {
		parts = append(parts, region)
	}

	return strings.Join(parts, ", ")
}

func findExitDelta(r RunReport, family string) *ExitDelta {
	for _, d := range r.ExitDeltas {
		if d.Family == family {
			dd := d
			return &dd
		}
	}
	return nil
}

func uniqStrings(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
