// File: internal/report/model.go (complete file)

package report

import "time"

type PublicIPResult struct {
	Source string `json:"source"`
	Family string `json:"family"` // ipv4, ipv6, any
	IP     string `json:"ip,omitempty"`
	Error  string `json:"error,omitempty"`
}

type DnsLeakServer struct {
	IPAddress string `json:"ip_address"`
	Hostname  string `json:"hostname"`
	ISP       string `json:"isp"`
	City      string `json:"city"`
	Country   string `json:"country"`
}

type Snapshot struct {
	TimestampUTC time.Time        `json:"timestamp_utc"`
	PublicIPs    []PublicIPResult `json:"public_ips"`
	DnsRecursors []string         `json:"dns_recursors,omitempty"`
	DnsLeak      []DnsLeakServer  `json:"dnsleaktest,omitempty"`
	StunObserved []string         `json:"stun_observed,omitempty"`
	Notes        []string         `json:"notes,omitempty"`
}
