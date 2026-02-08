// File: internal/monitor/monitor_test.go (complete file)

package monitor

import (
	"testing"
	"time"

	"github.com/baptistax/vpn-leak-identifier/internal/report"
)

func TestChanged_PublicIPChange(t *testing.T) {
	a := &report.Snapshot{
		TimestampUTC: time.Now().UTC(),
		PublicIPs: []report.PublicIPResult{
			{Source: "ipify", Family: "ipv4", IP: "1.1.1.1"},
		},
	}
	b := &report.Snapshot{
		TimestampUTC: time.Now().UTC(),
		PublicIPs: []report.PublicIPResult{
			{Source: "ipify", Family: "ipv4", IP: "2.2.2.2"},
		},
	}

	if !changed(a, b) {
		t.Fatalf("expected change")
	}
}

func TestChanged_NoChange(t *testing.T) {
	a := &report.Snapshot{
		TimestampUTC: time.Now().UTC(),
		PublicIPs: []report.PublicIPResult{
			{Source: "ipify", Family: "ipv4", IP: "1.1.1.1"},
		},
		DnsRecursors: []string{"9.9.9.9"},
		StunObserved: []string{"1.1.1.1"},
		DnsLeak:      []report.DnsLeakServer{{IPAddress: "9.9.9.9"}},
	}
	b := &report.Snapshot{
		TimestampUTC: time.Now().UTC(),
		PublicIPs: []report.PublicIPResult{
			{Source: "ipify", Family: "ipv4", IP: "1.1.1.1"},
		},
		DnsRecursors: []string{"9.9.9.9"},
		StunObserved: []string{"1.1.1.1"},
		DnsLeak:      []report.DnsLeakServer{{IPAddress: "9.9.9.9"}},
	}

	if changed(a, b) {
		t.Fatalf("expected no change")
	}
}
