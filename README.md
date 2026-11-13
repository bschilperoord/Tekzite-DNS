# Tekzite DNS

**Experimental Python DNS server**, with JSON authoritative zones, optional on-demand SQLite caching, RPZ QNAME filtering, FDNS data, DNS snapshots, WAN learning, IPv4/IPv6 and UDP/TCP support.

> **v0.1.0-rc5: experimental release candidate, not production-certified.** This is a sanitized snapshot, not yet reconciled against the live router01 service. Do not expose it as a public recursive resolver.

## Design philosophy

Tekzite DNS is built around two complementary principles:

1. **Eliminate unnecessary external DNS requests.**
2. **Preserve reliability without sacrificing correctness.**

**Remember intelligently. Verify when necessary. Never waste resources without a reason.**

DNS answers should not be forgotten merely because a process restarts. Persistent local knowledge can reduce repeat lookups, while sensible refresh and expiry policies protect against outdated records. An address remaining unchanged in the past does not guarantee it is still correct, so stale records must be handled carefully and transparently.

The long-term goal is a **local-first, privacy-respecting, resource-efficient DNS server** that only makes external requests when justified. These are project design goals, not a claim that all adaptive caching behavior is already implemented or that public DNS can operate with no external information.

## Requirements

- Python 3.10+
- `dnspython` (see `requirements.txt`)
- Optional `dig` for WAN resolution and `curl` for snapshot downloads.

## Run a localhost-only test server

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python src/tekzite_dns.py --zone examples/zone.json --local-only --listen 127.0.0.1 --port 5533
```

In another terminal:

```bash
dig @127.0.0.1 -p 5533 www.tekzite.test A
```

The demo A response should be `192.0.2.42`, a documentation-only address.

## Security and deployment

- Default client ACL permits loopback only. Non-loopback listeners require explicit `--allow-client CIDR` networks. Always enforce firewall restrictions too.
- Limit request workers with `--max-workers` (default 32 per listener).
- Optional per-client rate limiting: `--rate-limit 100 --rate-burst 200`. Disabled by default; peers sharing a NAT address share the bucket.
- `--ondemand-db` uses the system DNS resolver and SQLite: avoid forwarding loops; use Unbound as the upstream DNSSEC validator.
- `--lan-domain` provides an explicit private-address rebinding exception; scope it narrowly.
- RPZ support is limited to QNAME/CNAME triggers, not all RPZ trigger types.
- Do not enable `--trace` during normal operation because logs may reveal query names.
- Run as an unprivileged account. See `deploy/tekzite-dns.service.example`, which is designed for localhost-only operation.
- Do **not** replace any running router service without checking systemd drop-ins and the effective `ExecStart`.

## Automated tests

```bash
python -m compileall -q src tests
python -m unittest discover -s tests -v
python tools/soak.py --duration 60 --qps 40 --workers 8 --output soak-results
```

The isolated soak script launches a temporary localhost-only DNS service on a high port. It records latency percentiles, response counts, process CPU/RSS/thread samples and logs. A longer staging run:

```bash
python tools/soak.py --duration 43200 --qps 20 --workers 8 --output soak-results
```

**Limitations:** Short localhost tests do not establish 12–24-hour stability or validate WAN recursion, RPZ behavior, upstream DNSSEC, and production-sized SQLite databases. See [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) and [CHANGELOG.md](CHANGELOG.md).

## License

Tekzite DNS is free and open-source software licensed under the [MIT License](LICENSE). You may use, copy, modify, redistribute, sublicense and sell copies, including modified versions, provided that you retain the copyright and license notice. No publication of modifications is required. The MIT grant applies to code and materials the copyright holder has rights to license; third-party dependencies retain their own licenses.

## Vulnerabilities

See [SECURITY.md](SECURITY.md). Please report sensitive security issues privately rather than in public GitHub issues.


## Native DNS-over-TLS (experimental, RC6)

Tekzite DNS includes an **optional TLS/TCP DoT listener**, sharing the existing resolver, client allowlist, rate limit and DNS-over-TCP framing. Plain DNS remains unchanged. The server supports TLS 1.2+ (including TLS 1.3 when negotiated). DoT is not enabled unless the `--dot-listen`, `--dot-cert`, and `--dot-key` options are given together.

Staging on a separate local-only port (do not modify your live systemd service yet):

```bash
python src/tekzite_dns.py --zone examples/zone.json --local-only \
  --listen 127.0.0.1 --port 5533 \
  --dot-listen 127.0.0.1 --dot-port 8853 \
  --dot-cert /etc/tekzite-dns/tls/fullchain.pem \
  --dot-key /etc/tekzite-dns/tls/privkey.pem
```

Inspect the certificate/handshake with:

```bash
openssl s_client -connect 127.0.0.1:8853 \
  -servername basmediaserver.ddns.net \
  -verify_hostname basmediaserver.ddns.net -verify_return_error </dev/null
```

For a LAN listener use `--dot-listen PRIVATE_LAN_IP --dot-port 8853`, explicitly permit the LAN's CIDR via `--allow-client`, and restrict the firewall to trusted clients. A client's DoT authentication hostname must match the server certificate. `dig @IP -p 8853` is **not** a DoT query: use a DNS client that supports TLS.

The TLS certificate is loaded at service startup. After automatic renewal/certificate transfer the DoT process requires a planned restart to load the new certificate; transferring files alone does not trigger reload. Restrict the SSH certificate-deployment key to its installer. DoT encrypts **client-to-Tekzite traffic**, not necessarily Tekzite's upstream traffic, and does not itself validate DNSSEC.
