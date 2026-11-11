# Tekzite DNS

**Experimental Python DNS server**, with JSON authoritative zones, optional on-demand SQLite caching, RPZ QNAME filtering, FDNS data, DNS snapshots, WAN learning, IPv4/IPv6 and UDP/TCP support.

> **v0.1.0-rc5: experimental release candidate, not production-certified.** This is a sanitized snapshot, not yet reconciled against the live router01 service. Do not expose it as a public recursive resolver.

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

No open-source license has been granted. Confirm code ownership and third-party provenance before adding one. Public visibility is not permission to redistribute or modify.

## Vulnerabilities

See [SECURITY.md](SECURITY.md). Please report sensitive security issues privately rather than in public GitHub issues.
