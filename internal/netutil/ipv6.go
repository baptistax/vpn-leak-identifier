// File: internal/netutil/ipv6.go (complete file)

package netutil

import "net"

// HasGlobalIPv6 reports whether the host appears to have at least one global IPv6 address.
// Link-local, ULA, multicast, loopback and unspecified addresses are ignored.
func HasGlobalIPv6() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip := addrToIP(a)
			if ip == nil {
				continue
			}
			ip16 := ip.To16()
			if ip16 == nil {
				continue
			}
			// Skip IPv4-mapped.
			if ip16.To4() != nil {
				continue
			}
			if ip16.IsUnspecified() || ip16.IsLoopback() {
				continue
			}
			if ip16.IsLinkLocalUnicast() {
				continue
			}
			// ULA fc00::/7
			if ip16[0]&0xfe == 0xfc {
				continue
			}
			// Multicast ff00::/8
			if ip16[0] == 0xff {
				continue
			}
			return true
		}
	}

	return false
}

func addrToIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		return nil
	}
}
