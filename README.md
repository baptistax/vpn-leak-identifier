# vpnleakidentifier

A small CLI to help validate VPN behavior:
- Exit IP (IPv4/IPv6) + best-effort geo (via `ident.me/json`, with `tnedi.me` fallback)
- DNS recursor hints (`ns.ident.me`)
- Optional STUN observed public IP (UDP)

## Quick start

```bash
go build -o vpnleakidentifier ./cmd/vpnleakidentifier

# Default: 30s run intended for kill-switch validation
# (recommended: start with VPN ON, then disable VPN during the 30s window)
./vpnleakidentifier

# Fast VPN-only test (5s, no kill-switch verdict)
./vpnleakidentifier test -nks
```

## Outputs

Each run writes to `./exports/run_<UTC_TIMESTAMP>/`:
- `run.json`
- `run.txt`

Snapshot/monitor commands write:
- `snapshot.json`
- `snapshot.txt`

## Notes

- The default mode does **not** sniff raw traffic; it infers leaks via exit-IP/geo deltas and connectivity transitions.
- Admin privileges are **not** required in the default mode.
