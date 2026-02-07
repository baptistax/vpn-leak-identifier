// File: internal/report/run.go (complete file)

package report

import "time"

type RunMode string

const (
	RunModeKillSwitch RunMode = "kill-switch"
	RunModeVPNOnly    RunMode = "vpn-only"
)

type GeoInfo struct {
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	Region      string `json:"region,omitempty"`
	City        string `json:"city,omitempty"`
	ISP         string `json:"isp,omitempty"`
	ASN         string `json:"asn,omitempty"`
	Timezone    string `json:"timezone,omitempty"`
}

type ExitInfo struct {
	Family string  `json:"family"`
	IP     string  `json:"ip,omitempty"`
	Geo    GeoInfo `json:"geo,omitempty"`
	Source string  `json:"source,omitempty"`
	Error  string  `json:"error,omitempty"`
}

type ProbeSet struct {
	AtUTC        time.Time `json:"at_utc"`
	AtSec        int       `json:"at_sec"`
	ExitV4       ExitInfo  `json:"exit_v4"`
	ExitV6       ExitInfo  `json:"exit_v6"`
	DNSRecursors []string  `json:"dns_recursors,omitempty"`
	StunObserved []string  `json:"stun_observed,omitempty"`
	Online       bool      `json:"online"`
	Notes        []string  `json:"notes,omitempty"`
}

type ExitDelta struct {
	Family string   `json:"family"`
	From   ExitInfo `json:"from"`
	To     ExitInfo `json:"to"`
	AtSec  int      `json:"at_sec"`
}

type DNSDelta struct {
	From  []string `json:"from"`
	To    []string `json:"to"`
	AtSec int      `json:"at_sec"`
}

type Verdict struct {
	Overall    string `json:"overall"`               // PASS|FAIL|INCONCLUSIVE|OK
	KillSwitch string `json:"kill_switch,omitempty"` // PASS|FAIL|NOT TESTED|INCONCLUSIVE
	Reason     string `json:"reason,omitempty"`
}

type RunReport struct {
	RunID       string        `json:"run_id"`
	StartedUTC  time.Time     `json:"started_utc"`
	Mode        RunMode       `json:"mode"`
	Duration    time.Duration `json:"duration"`
	Interval    time.Duration `json:"interval"`
	BaselineWin time.Duration `json:"baseline_window"`

	Baseline ProbeSet `json:"baseline"`
	End      ProbeSet `json:"end"`

	ExitDeltas   []ExitDelta `json:"exit_deltas,omitempty"`
	DNSDelta     *DNSDelta   `json:"dns_delta,omitempty"`
	OfflineAtSec *int        `json:"offline_at_sec,omitempty"`
	Notes        []string    `json:"notes,omitempty"`

	Probes  []ProbeSet `json:"probes,omitempty"`
	Verdict Verdict    `json:"verdict"`
}

func NewRunReport(mode RunMode, duration, interval, baselineWin time.Duration) RunReport {
	return RunReport{
		RunID:       time.Now().UTC().Format("20060102_150405"),
		StartedUTC:  time.Now().UTC(),
		Mode:        mode,
		Duration:    duration,
		Interval:    interval,
		BaselineWin: baselineWin,
	}
}

func NewProbeSet() ProbeSet {
	return ProbeSet{
		AtUTC: time.Now().UTC(),
	}
}

func (ps *ProbeSet) DeriveOnline() {
	// Consider the host online if at least one exit probe produced an IP.
	if ps.ExitV4.IP != "" && ps.ExitV4.Error == "" {
		ps.Online = true
		return
	}
	if ps.ExitV6.IP != "" && ps.ExitV6.Error == "" {
		ps.Online = true
		return
	}
	// STUN-only connectivity can happen even if HTTPS is blocked.
	if len(ps.StunObserved) > 0 {
		ps.Online = true
		return
	}
	ps.Online = false
}

func (r *RunReport) MaybeRecordExitDelta(baseline, current ProbeSet) {
	// Record the first time the exit IP changes from the baseline.
	// This is enough to "prove" a leak for the user, without spamming output.
	if baseline.ExitV4.IP != "" && current.ExitV4.IP != "" && baseline.ExitV4.IP != current.ExitV4.IP {
		if !r.hasExitDelta("ipv4") {
			r.ExitDeltas = append(r.ExitDeltas, ExitDelta{
				Family: "ipv4",
				From:   baseline.ExitV4,
				To:     current.ExitV4,
				AtSec:  current.AtSec,
			})
		}
	}
	if baseline.ExitV6.IP != "" && current.ExitV6.IP != "" && baseline.ExitV6.IP != current.ExitV6.IP {
		if !r.hasExitDelta("ipv6") {
			r.ExitDeltas = append(r.ExitDeltas, ExitDelta{
				Family: "ipv6",
				From:   baseline.ExitV6,
				To:     current.ExitV6,
				AtSec:  current.AtSec,
			})
		}
	}
}

func (r *RunReport) MaybeRecordDNSDelta(baseline, current ProbeSet) {
	if len(baseline.DNSRecursors) == 0 || len(current.DNSRecursors) == 0 {
		return
	}
	if !equalStringSets(baseline.DNSRecursors, current.DNSRecursors) && r.DNSDelta == nil {
		r.DNSDelta = &DNSDelta{
			From:  baseline.DNSRecursors,
			To:    current.DNSRecursors,
			AtSec: current.AtSec,
		}
	}
}

func (r *RunReport) hasExitDelta(family string) bool {
	for _, d := range r.ExitDeltas {
		if d.Family == family {
			return true
		}
	}
	return false
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ma := make(map[string]int, len(a))
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

func (r *RunReport) Finish() {
	// If the baseline never established connectivity, no reliable validation can be done.
	if r.Mode == RunModeKillSwitch && !r.Baseline.Online {
		r.Verdict = Verdict{
			Overall:    "INCONCLUSIVE",
			KillSwitch: "INCONCLUSIVE",
			Reason:     "Baseline connectivity could not be established during the baseline window.",
		}
		return
	}

	switch r.Mode {
	case RunModeVPNOnly:
		r.Verdict = Verdict{
			Overall: "OK",
			Reason:  "VPN test completed (no kill-switch validation).",
		}
		return
	default:
		// Kill-switch mode.
		if len(r.ExitDeltas) > 0 {
			r.Verdict = Verdict{
				Overall:    "FAIL",
				KillSwitch: "FAIL",
				Reason:     "Exit IP changed during the test window (traffic observed outside the initial VPN exit).",
			}
			return
		}
		if r.OfflineAtSec != nil {
			r.Verdict = Verdict{
				Overall:    "PASS",
				KillSwitch: "PASS",
				Reason:     "Connectivity dropped during the test window (consistent with kill-switch behavior).",
			}
			return
		}
		r.Verdict = Verdict{
			Overall:    "NOT TESTED",
			KillSwitch: "NOT TESTED",
			Reason:     "No VPN drop/leak was observed during the test window. Disable VPN during the run to validate kill-switch behavior.",
		}
	}
}
