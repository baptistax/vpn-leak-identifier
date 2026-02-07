// File: internal/leaks/dns_identme.go (complete file)

package leaks

import (
	"errors"
	"net"
)

func LookupRecursorIPsViaIdentMe() ([]string, error) {
	// ns.ident.me (and ns4/ns6) returns the public IP of the DNS recursors used by the system.
	names := []string{"ns.ident.me", "ns4.ident.me", "ns6.ident.me"}

	var out []string
	seen := map[string]bool{}

	for _, name := range names {
		ips, err := net.LookupIP(name)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			s := ip.String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}

	if len(out) == 0 {
		return nil, errors.New("no IPs returned from ns.ident.me lookups")
	}
	return out, nil
}
