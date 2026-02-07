// File: internal/monitor/monitor.go (complete file)

package monitor

import (
	"context"
	"time"

	"github.com/baptistax/vpnleakidentifier/internal/app"
	"github.com/baptistax/vpnleakidentifier/internal/report"
)

type Event struct {
	AtUTC    time.Time
	Kind     string // "changed"
	Message  string
	Previous *report.Snapshot
	Current  *report.Snapshot
}

type Options struct {
	Interval time.Duration
	Timeout  time.Duration
	Snapshot app.SnapshotOptions
}

func Run(ctx context.Context, opt Options, onEvent func(Event)) {
	var prev *report.Snapshot

	ticker := time.NewTicker(opt.Interval)
	defer ticker.Stop()

	take := func() {
		snapCtx, cancel := context.WithTimeout(ctx, opt.Timeout)
		s := app.TakeSnapshot(snapCtx, opt.Snapshot)
		cancel()

		if prev != nil {
			if changed(prev, &s) {
				onEvent(Event{
					AtUTC:    time.Now().UTC(),
					Kind:     "changed",
					Message:  "snapshot changed",
					Previous: prev,
					Current:  &s,
				})
			}
		}
		prev = &s
	}

	// First snapshot immediately.
	take()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			take()
		}
	}
}

func changed(a, b *report.Snapshot) bool {
	// Conservative change detector: compare public IP lists + DNS recursor list + STUN observed list.
	// This is intentionally simple for the skeleton.

	if !samePublicIPs(a.PublicIPs, b.PublicIPs) {
		return true
	}
	if !sameStringSet(a.DnsRecursors, b.DnsRecursors) {
		return true
	}
	if !sameStringSet(a.StunObserved, b.StunObserved) {
		return true
	}

	// dnsleaktest.com data can be noisy; compare only observed IP addresses.
	if !sameDNSLeakIPs(a.DnsLeak, b.DnsLeak) {
		return true
	}

	return false
}

func samePublicIPs(a, b []report.PublicIPResult) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Family != b[i].Family || a[i].IP != b[i].IP || a[i].Error != b[i].Error {
			return false
		}
	}
	return true
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ma := map[string]int{}
	for _, s := range a {
		ma[s]++
	}
	for _, s := range b {
		if ma[s] == 0 {
			return false
		}
		ma[s]--
	}
	for _, v := range ma {
		if v != 0 {
			return false
		}
	}
	return true
}

func sameDNSLeakIPs(a, b []report.DnsLeakServer) bool {
	aa := make([]string, 0, len(a))
	bb := make([]string, 0, len(b))

	for _, s := range a {
		if s.IPAddress != "" {
			aa = append(aa, s.IPAddress)
		}
	}
	for _, s := range b {
		if s.IPAddress != "" {
			bb = append(bb, s.IPAddress)
		}
	}

	return sameStringSet(aa, bb)
}
