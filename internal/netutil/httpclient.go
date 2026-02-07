// File: internal/netutil/httpclient.go (complete file)

package netutil

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"
)

func HTTPClientForFamily(family string) *http.Client {
	dialer := &net.Dialer{
		Timeout:   6 * time.Second,
		KeepAlive: 15 * time.Second,
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			switch strings.ToLower(family) {
			case "ipv4":
				return dialer.DialContext(ctx, "tcp4", addr)
			case "ipv6":
				return dialer.DialContext(ctx, "tcp6", addr)
			default:
				return dialer.DialContext(ctx, network, addr)
			}
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
}
