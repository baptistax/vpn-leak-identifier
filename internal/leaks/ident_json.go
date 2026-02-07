// File: internal/leaks/ident_json.go (complete file)

package leaks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type IdentInfo struct {
	IP          string
	Country     string
	CountryCode string
	Region      string
	City        string
	ISP         string
	ASN         string
	Timezone    string
	Raw         map[string]any
}

func FetchIdentInfo(ctx context.Context, client *http.Client, family string) (IdentInfo, error) {
	// The ident.me service supports /json and host prefixes 4. and 6. for forcing address family.
	// A mirror is available at tnedi.me. Source: api.ident.me documentation.
	var hosts []string
	switch strings.ToLower(family) {
	case "ipv4":
		hosts = []string{"4.ident.me", "4.tnedi.me"}
	case "ipv6":
		hosts = []string{"6.ident.me", "6.tnedi.me"}
	default:
		hosts = []string{"ident.me", "tnedi.me"}
	}

	var lastErr error
	for _, host := range hosts {
		info, err := fetchIdentInfoFromHost(ctx, client, "https://"+host+"/json")
		if err == nil {
			return info, nil
		}
		lastErr = err
	}

	if lastErr == nil {
		lastErr = errors.New("ident fetch failed")
	}
	return IdentInfo{}, lastErr
}

func fetchIdentInfoFromHost(ctx context.Context, client *http.Client, url string) (IdentInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return IdentInfo{}, err
	}
	req.Header.Set("User-Agent", "vpnleakidentifier/0.1")

	resp, err := client.Do(req)
	if err != nil {
		return IdentInfo{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return IdentInfo{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return IdentInfo{}, fmt.Errorf("http status %d", resp.StatusCode)
	}

	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return IdentInfo{}, errors.New("empty response body")
	}

	// Expected JSON object, but tolerate plaintext IP if upstream changes.
	if !strings.HasPrefix(trimmed, "{") {
		if isLikelyIP(trimmed) {
			return IdentInfo{IP: trimmed, Raw: map[string]any{"ip": trimmed}}, nil
		}
		return IdentInfo{}, errors.New("unexpected non-json response")
	}

	var raw map[string]any
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		return IdentInfo{}, err
	}

	info := IdentInfo{Raw: raw}

	// Best-effort field extraction (fields are not guaranteed stable).
	info.IP = pickString(raw, "ip", "ip_address", "address", "query")
	info.Country = pickString(raw, "country", "country_name")
	info.CountryCode = pickString(raw, "cc", "country_code", "countryCode")
	info.Region = pickString(raw, "region", "region_name", "regionName", "state")
	info.City = pickString(raw, "city", "town")
	info.ISP = pickString(raw, "isp", "org", "organization", "as_org")
	info.ASN = pickString(raw, "asn", "as", "as_number", "asNumber")
	info.Timezone = pickString(raw, "tz", "timezone", "time_zone", "timeZone")

	// Normalize common "as" field like "AS123 Example".
	if info.ASN == "" {
		if as := pickString(raw, "as"); as != "" {
			info.ASN = as
		}
	}

	if info.IP == "" {
		return IdentInfo{}, errors.New("missing ip field in ident JSON")
	}

	return info, nil
}

func pickString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		v, ok := m[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case string:
			if strings.TrimSpace(t) != "" {
				return strings.TrimSpace(t)
			}
		case float64:
			// It is intentionally converted without decimals.
			return fmt.Sprintf("%.0f", t)
		default:
			// ignore
		}
	}
	return ""
}

func isLikelyIP(s string) bool {
	// This is a minimal heuristic; it is intentionally permissive.
	s = strings.TrimSpace(s)
	if strings.Count(s, ".") == 3 {
		return true
	}
	if strings.Contains(s, ":") {
		return true
	}
	return false
}

// Small helper to avoid unused import in older builds.
var _ = time.Second
