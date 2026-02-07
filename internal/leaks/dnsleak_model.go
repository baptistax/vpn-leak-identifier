// File: internal/leaks/dnsleak_model.go (complete file)

package leaks

type DNSLeakServer struct {
	IPAddress string `json:"ip_address"`
	Hostname  string `json:"hostname"`
	ISP       string `json:"isp"`
	City      string `json:"city"`
	Country   string `json:"country"`
}
