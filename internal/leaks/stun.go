// File: internal/leaks/stun.go (complete file)

package leaks

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"time"
)

const (
	stunBindingRequest  uint16 = 0x0001
	stunBindingResponse uint16 = 0x0101

	stunMagicCookie uint32 = 0x2112A442

	stunAttrXORMappedAddress uint16 = 0x0020

	stunFamilyIPv4 byte = 0x01
	stunFamilyIPv6 byte = 0x02
)

func StunObservedIPs(ctx context.Context, stunServers []string) ([]string, error) {
	// Returns distinct public IPs observed through STUN binding requests (UDP).
	// This is a minimal STUN implementation to avoid external dependencies.
	//
	// It does not attempt full RFC compliance; it only supports parsing XOR-MAPPED-ADDRESS.

	var out []string
	seen := map[string]bool{}

	dialer := net.Dialer{Timeout: 6 * time.Second}

	for _, server := range stunServers {
		if server == "" {
			continue
		}

		c, err := dialer.DialContext(ctx, "udp", server)
		if err != nil {
			continue
		}

		txid, err := newTxID()
		if err != nil {
			_ = c.Close()
			continue
		}

		req := buildBindingRequest(txid)
		_, err = c.Write(req)
		if err != nil {
			_ = c.Close()
			continue
		}

		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))

		buf := make([]byte, 1500)
		n, err := c.Read(buf)
		_ = c.Close()
		if err != nil || n < 20 {
			continue
		}

		ip, err := parseXORMappedAddress(buf[:n], txid)
		if err != nil {
			continue
		}

		if ip != "" && !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}

	if len(out) == 0 {
		return nil, errors.New("no STUN responses")
	}
	return out, nil
}

func newTxID() ([12]byte, error) {
	var txid [12]byte
	_, err := rand.Read(txid[:])
	return txid, err
}

func buildBindingRequest(txid [12]byte) []byte {
	// STUN header is 20 bytes:
	//  0-1: message type
	//  2-3: message length (attributes only)
	//  4-7: magic cookie
	//  8-19: transaction id
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(b[2:4], 0)
	binary.BigEndian.PutUint32(b[4:8], stunMagicCookie)
	copy(b[8:20], txid[:])
	return b
}

func parseXORMappedAddress(pkt []byte, txid [12]byte) (string, error) {
	if len(pkt) < 20 {
		return "", errors.New("stun: short packet")
	}

	msgType := binary.BigEndian.Uint16(pkt[0:2])
	if msgType != stunBindingResponse {
		// Some servers respond with 0x0111 or other types (e.g. error). Ignore.
	}

	msgLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if 20+msgLen > len(pkt) {
		return "", errors.New("stun: invalid length")
	}

	cookie := binary.BigEndian.Uint32(pkt[4:8])
	if cookie != stunMagicCookie {
		return "", errors.New("stun: bad magic cookie")
	}

	attrs := pkt[20 : 20+msgLen]
	for len(attrs) >= 4 {
		typ := binary.BigEndian.Uint16(attrs[0:2])
		l := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+l > len(attrs) {
			break
		}
		val := attrs[4 : 4+l]

		if typ == stunAttrXORMappedAddress {
			ip, err := decodeXORMappedAddress(val, txid)
			if err != nil {
				return "", err
			}
			return ip, nil
		}

		// Attributes are padded to a multiple of 4 bytes.
		adv := 4 + l
		if adv%4 != 0 {
			adv += 4 - (adv % 4)
		}
		attrs = attrs[adv:]
	}

	return "", errors.New("stun: xor-mapped-address not found")
}

func decodeXORMappedAddress(val []byte, txid [12]byte) (string, error) {
	// XOR-MAPPED-ADDRESS:
	//  0: 0x00
	//  1: family (0x01 v4, 0x02 v6)
	//  2-3: x-port
	//  4- : x-address
	if len(val) < 4 {
		return "", errors.New("stun: xor-mapped-address too short")
	}

	fam := val[1]
	xport := binary.BigEndian.Uint16(val[2:4])
	port := xport ^ uint16(stunMagicCookie>>16)

	switch fam {
	case stunFamilyIPv4:
		if len(val) < 8 {
			return "", errors.New("stun: ipv4 addr too short")
		}
		xaddr := binary.BigEndian.Uint32(val[4:8])
		addr := xaddr ^ stunMagicCookie
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, addr)
		_ = port // currently unused, kept for future diagnostics
		return ip.String(), nil

	case stunFamilyIPv6:
		if len(val) < 20 {
			return "", errors.New("stun: ipv6 addr too short")
		}
		ip := make(net.IP, 16)
		// XOR first 4 bytes with cookie.
		for i := 0; i < 4; i++ {
			ip[i] = val[4+i] ^ byte(stunMagicCookie>>(24-8*i))
		}
		// XOR remaining 12 bytes with transaction ID.
		for i := 0; i < 12; i++ {
			ip[4+i] = val[8+i] ^ txid[i]
		}
		_ = port
		return ip.String(), nil

	default:
		return "", errors.New("stun: unsupported family")
	}
}
