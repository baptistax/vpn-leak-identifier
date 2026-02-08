// File: internal/leaks/dns_dnsleaktest.go (complete file)

package leaks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/baptistax/vpn-leak-identifier/internal/netutil"
)

func DNSLeakTestViaDNSLeakTestCom(ctx context.Context, queries int) ([]DNSLeakServer, error) {
	// Best-effort replication of dnsleaktest.com flow:
	// - POST identifiers
	// - Resolve <id>.test.dnsleaktest.com via system resolver
	// - POST queries to servers-for-result endpoint
	//
	// This can fail due to rate limits or connectivity issues.

	if queries <= 0 {
		queries = 6
	}
	if queries > 36 {
		queries = 36
	}

	type identifiersPayload struct {
		Identifiers []string `json:"identifiers"`
	}
	type serversPayload struct {
		Queries []string `json:"queries"`
	}

	client := netutil.HTTPClientForFamily("any")

	makeID := func() string {
		const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
		parts := []int{8, 4, 4, 4, 12}

		var b strings.Builder
		b.Grow(36)

		for i, n := range parts {
			if i > 0 {
				b.WriteByte('-')
			}
			for j := 0; j < n; j++ {
				b.WriteByte(letters[rand.Intn(len(letters))])
			}
		}
		return b.String()
	}

	rand.Seed(time.Now().UnixNano())

	ids := make([]string, 0, queries)
	for i := 0; i < queries; i++ {
		ids = append(ids, makeID())
	}

	// Pre-send identifiers (ignore errors).
	{
		payload, _ := json.Marshal(identifiersPayload{Identifiers: ids})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://www.dnsleaktest.com/api/v1/identifiers", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json;charset=UTF-8")
		req.Header.Set("User-Agent", "vpnleakidentifier/0.1")
		resp, err := client.Do(req)
		if err == nil && resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}

	// Trigger DNS lookups.
	for _, id := range ids {
		_, _ = net.LookupHost(id + ".test.dnsleaktest.com")
	}

	payload, err := json.Marshal(serversPayload{Queries: ids})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://www.dnsleaktest.com/api/v1/servers-for-result", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("User-Agent", "vpnleakidentifier/0.1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}

	var servers []DNSLeakServer
	if err := json.Unmarshal(body, &servers); err != nil {
		return nil, err
	}
	if len(servers) == 0 {
		return nil, errors.New("no recursors returned by dnsleaktest.com")
	}
	return servers, nil
}
