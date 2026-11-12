# Changelog

## Licensing (2026-11-12)

- Published the MIT License, allowing use, modification, redistribution, sublicensing and commercial distribution with the copyright and license notice preserved.

## Unreleased (v0.1.0 release candidate)

- Initial GitHub-ready release structure based on `tekzite_dns_lab_v9_improved.py` snapshot.
- Added offline smoke tests and GitHub Actions CI.
- Restricted on-demand recursion from wildcard/public listen IPs at startup.
- Added sample local-only systemd service and documented security/release gates.

## Unreleased (hardening iteration 1)

- Added repeatable `--allow-client CIDR` DNS client allowlist, with loopback-only default.
- Non-loopback listeners now require an explicitly configured client allowlist.
- Enforced client restrictions on both UDP and TCP; added IPv4-mapped IPv6 handling.
- Expanded offline tests to include allowlist decisions and real UDP/TCP responses.

### Protocol hardening (2026-11-11)

- Validate EDNS(0) option framing and reject truncated option headers/payloads.
- Reject reserved DNS header Z bit and reserved EDNS flag bits while permitting AD/CD and EDNS DO.
- Add regression coverage for EDNS version negotiation, duplicate OPT, trailing bytes, and invalid DNS compression pointers.
- Add deterministic random-packet and mutated-query robustness tests (2,000 generated payloads plus truncation sweep).
- Test suite now includes 25 passing tests. This is a release candidate, not a completed independent security audit.

### Resource hardening (2026-11-11)

- Add configurable per-listener maximum request worker threads (`--max-workers`; default 32).
- Add opt-in per-source-IP token-bucket rate limiting (`--rate-limit`, `--rate-burst`) shared across UDP/TCP and listeners.
- Bound token-bucket peer state to 4096; reject unseen peers at capacity until stale entries can be reclaimed.
- Increase TCP listen backlog to 64; existing TCP session timeouts and per-connection query cap remain.
- Add UDP integration tests for rate limiting and 100-query concurrent smoke test.
- Suite expanded to 31 passing tests; long-running load and full SQLite contention tests are still pending.

## 0.1.0-rc4 (2026-11-11)

- Added opportunistic, time-gated SQLite expiration cleanup on on-demand cache writes (up to 500 expired records per table per pass).
- Added indexed expiration columns to avoid full-table scans during maintenance.
- Closed the SQLite initialization connection explicitly.
- Added SQLite writer contention, cache preservation, 1,000 UDP query and 100 TCP query tests (36 tests total).
- Documented staging scope, CI boundaries and remaining release gates.

## 0.1.0-rc5 (2026-11-11)

- Added isolated localhost-only authoritative DNS soak/load tool, with JSON
  metrics, p50/p95/p99 latency, status counts, process RSS/CPU/thread samples,
  and automatic child process teardown.
- Wired a 5-second smoke run into GitHub Actions CI and documented 12/24-hour
  staging commands and the separate live-feature validation requirements.
- Initial 12-second baseline: 480 successful requests out of 480, zero timeouts;
  no recursive, SQLite or RPZ behaviors exercised in this baseline.
