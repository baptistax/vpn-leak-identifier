// File: internal/app/test.go (complete file)

package app

import (
	"context"
	"net/http"
	"time"

	"github.com/baptistax/vpn-leak-identifier/internal/leaks"
	"github.com/baptistax/vpn-leak-identifier/internal/netutil"
	"github.com/baptistax/vpn-leak-identifier/internal/report"
)

type TestOptions struct {
	Mode        report.RunMode
	Duration    time.Duration
	Baseline    time.Duration
	Interval    time.Duration
	EnableSTUN  bool
	StunServers []string
}

func RunTest(ctx context.Context, opt TestOptions) report.RunReport {
	if opt.Duration <= 0 {
		opt.Duration = 30 * time.Second
	}
	if opt.Baseline <= 0 {
		opt.Baseline = 5 * time.Second
	}
	if opt.Interval <= 0 {
		opt.Interval = 1 * time.Second
	}

	r := report.NewRunReport(opt.Mode, opt.Duration, opt.Interval, opt.Baseline)

	ipv4Client := netutil.HTTPClientForFamily("ipv4")
	ipv6Client := netutil.HTTPClientForFamily("ipv6")
	hasIPv6 := netutil.HasGlobalIPv6()

	start := time.Now()
	deadline := start.Add(opt.Duration)

	// Baseline phase: keep the last successful probe as baseline.
	var baseline report.ProbeSet
	baselineDeadline := start.Add(opt.Baseline)
	for time.Now().Before(baselineDeadline) {
		ps := takeProbeSet(ctx, start, ipv4Client, ipv6Client, hasIPv6, opt)
		r.Probes = append(r.Probes, ps)
		if ps.Online {
			baseline = ps
			r.Baseline = ps
		}
		if !sleepOrDone(ctx, opt.Interval) {
			break
		}
	}

	// If baseline was never online, still proceed but mark notes.
	if !baseline.Online {
		r.Notes = append(r.Notes, "baseline probes did not succeed (no connectivity or blocked)")
		r.Baseline = baseline
	}

	// Main phase.
	var last report.ProbeSet
	var consecutiveOffline int
	for time.Now().Before(deadline) {
		ps := takeProbeSet(ctx, start, ipv4Client, ipv6Client, hasIPv6, opt)
		r.Probes = append(r.Probes, ps)
		last = ps

		// Detect first exit deltas for v4/v6.
		r.MaybeRecordExitDelta(baseline, ps)
		r.MaybeRecordDNSDelta(baseline, ps)

		// Offline detection for kill-switch behavior.
		if baseline.Online && !ps.Online {
			consecutiveOffline++
			if consecutiveOffline == 2 && r.OfflineAtSec == nil {
				sec := ps.AtSec
				r.OfflineAtSec = &sec
			}
		} else {
			consecutiveOffline = 0
		}

		if !sleepOrDone(ctx, opt.Interval) {
			break
		}
	}

	r.End = last
	r.Finish()

	return r
}

func takeProbeSet(ctx context.Context, start time.Time, ipv4Client, ipv6Client *http.Client, hasIPv6 bool, opt TestOptions) report.ProbeSet {
	ps := report.NewProbeSet()
	ps.AtSec = int(time.Since(start).Seconds())

	// Exit IP + geo.
	{
		ctxp, cancel := context.WithTimeout(ctx, 3*time.Second)
		info, err := leaks.FetchIdentInfo(ctxp, ipv4Client, "ipv4")
		cancel()
		ps.ExitV4 = exitFromIdent("ipv4", info, err)
	}
	if hasIPv6 {
		ctxp, cancel := context.WithTimeout(ctx, 3*time.Second)
		info, err := leaks.FetchIdentInfo(ctxp, ipv6Client, "ipv6")
		cancel()
		ps.ExitV6 = exitFromIdent("ipv6", info, err)
	} else {
		ps.ExitV6 = report.ExitInfo{Family: "ipv6", Source: "ident.me/json", Error: "disabled"}
	}

	// DNS recursors hint.
	{
		ips, err := leaks.LookupRecursorIPsViaIdentMe()
		if err == nil {
			ps.DNSRecursors = ips
		} else {
			ps.Notes = append(ps.Notes, "ns.ident.me lookup failed: "+err.Error())
		}
	}

	// STUN observed.
	if opt.EnableSTUN {
		servers := opt.StunServers
		if len(servers) == 0 {
			servers = []string{
				"stun.l.google.com:19302",
				"stun1.l.google.com:19302",
				"stun2.l.google.com:19302",
			}
		}

		ctxp, cancel := context.WithTimeout(ctx, 6*time.Second)
		ips, err := leaks.StunObservedIPs(ctxp, servers)
		cancel()
		if err == nil {
			ps.StunObserved = ips
		} else {
			ps.Notes = append(ps.Notes, "stun failed: "+err.Error())
		}
	}

	ps.DeriveOnline()
	return ps
}

func exitFromIdent(family string, info leaks.IdentInfo, err error) report.ExitInfo {
	out := report.ExitInfo{
		Family: family,
		Source: "ident.me/json",
	}
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.IP = info.IP
	out.Geo = report.GeoInfo{
		Country:     info.Country,
		CountryCode: info.CountryCode,
		Region:      info.Region,
		City:        info.City,
		ISP:         info.ISP,
		ASN:         info.ASN,
		Timezone:    info.Timezone,
	}
	return out
}

func sleepOrDone(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
