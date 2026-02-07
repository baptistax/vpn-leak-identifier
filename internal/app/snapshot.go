// File: internal/app/snapshot.go (complete file)

package app

import (
	"context"
	"time"

	"github.com/baptistax/vpnleakidentifier/internal/leaks"
	"github.com/baptistax/vpnleakidentifier/internal/netutil"
	"github.com/baptistax/vpnleakidentifier/internal/report"
)

type SnapshotOptions struct {
	EnableDNSLeakTest bool
	EnableSTUN        bool
	DNSQueries        int
	StunServers       []string
}

func TakeSnapshot(ctx context.Context, opt SnapshotOptions) report.Snapshot {
	s := report.Snapshot{TimestampUTC: time.Now().UTC()}

	ipv4Client := netutil.HTTPClientForFamily("ipv4")
	ipv6Client := netutil.HTTPClientForFamily("ipv6")
	anyClient := netutil.HTTPClientForFamily("any")
	hasIPv6 := netutil.HasGlobalIPv6()

	// Public IP probes.
	{
		ip, err := leaks.FetchIPFromJSON(ctx, ipv4Client, "https://api.ipify.org?format=json")
		r := report.PublicIPResult{Source: "ipify", Family: "ipv4"}
		if err != nil {
			r.Error = err.Error()
		} else {
			r.IP = ip
		}
		s.PublicIPs = append(s.PublicIPs, r)
	}
	{
		r := report.PublicIPResult{Source: "ipify", Family: "ipv6"}
		if !hasIPv6 {
			r.Error = "disabled"
		} else {
			ip, err := leaks.FetchIPFromJSON(ctx, ipv6Client, "https://api6.ipify.org?format=json")
			if err != nil {
				r.Error = err.Error()
			} else {
				r.IP = ip
			}
		}
		s.PublicIPs = append(s.PublicIPs, r)
	}
	{
		ip, err := leaks.FetchIPFromJSON(ctx, anyClient, "https://api64.ipify.org?format=json")
		r := report.PublicIPResult{Source: "ipify", Family: "any"}
		if err != nil {
			r.Error = err.Error()
		} else {
			r.IP = ip
		}
		s.PublicIPs = append(s.PublicIPs, r)
	}

	// DNS recursors hint.
	if ips, err := leaks.LookupRecursorIPsViaIdentMe(); err == nil {
		s.DnsRecursors = ips
	} else {
		s.Notes = append(s.Notes, "ns.ident.me lookup failed: "+err.Error())
	}

	// dnsleaktest.com flow.
	if opt.EnableDNSLeakTest {
		servers, err := leaks.DNSLeakTestViaDNSLeakTestCom(ctx, opt.DNSQueries)
		if err != nil {
			s.Notes = append(s.Notes, "dnsleaktest.com failed: "+err.Error())
		} else {
			s.DnsLeak = mapDNSLeakServers(servers)
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
		ips, err := leaks.StunObservedIPs(ctx, servers)
		if err != nil {
			s.Notes = append(s.Notes, "stun failed: "+err.Error())
		} else {
			s.StunObserved = ips
		}
	}

	return s
}

func mapDNSLeakServers(in []leaks.DNSLeakServer) []report.DnsLeakServer {
	out := make([]report.DnsLeakServer, 0, len(in))
	for _, s := range in {
		out = append(out, report.DnsLeakServer{
			IPAddress: s.IPAddress,
			Hostname:  s.Hostname,
			ISP:       s.ISP,
			City:      s.City,
			Country:   s.Country,
		})
	}
	return out
}
