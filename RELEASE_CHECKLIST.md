# Release gates (not yet completed)

- [x] Source snapshot separated from home-specific deployment parameters
- [x] `.gitignore`, README, example zone, CI, offline protocol smoke tests
- [x] Guard against unspecified/public listen addresses for on-demand recursion
- [ ] Compare this file byte-for-byte with the **actual** router01 running `ExecStart` target; reconcile unit drop-ins
- [ ] Audit all user/network-controlled DNS message parsing with fuzz tests, malformed-compression tests, EDNS and TCP cases
- [ ] Confirm DNSSEC validation through Unbound and define AD/DO/CD behavior
- [x] Add default-deny non-loopback client CIDR ACLs for UDP and TCP (basic integration tests)
- [x] Add opt-in per-client rate limiting with basic UDP/in-memory tests
- [ ] Evaluate abusive recursive flood scenarios and NAT-shared clients under sustained load
- [ ] Review RPZ precedence, wildcard and CNAME-chain handling with large lists
- [ ] Evaluate bounded thread pools, timeouts, SQLite contention and database expiration/size behavior under load
- [ ] Assess upstream lookups and DNS-rebinding rules, including CNAME alias targets and private LAN overrides
- [ ] Check snapshot signature/integrity, remote source trust, supply-chain dependencies, and failure rollback
- [ ] Test restart/shutdown, TCP/UDP 53, IPv4/IPv6, simultaneous queries and memory footprint on Ubuntu
- [ ] Verify no secrets, addresses, backup data, or raw query logs before public push
- [ ] Choose license and confirm ownership of all committed code and data
- [ ] Tag release only after test results, review and real-world staging pass

## Protocol hardening checkpoint (2026-11-11)

- [x] EDNS(0) option framing and reserved-bit checks
- [x] Invalid DNS compression pointer regression tests
- [x] Deterministic malformed-input smoke tests
- [ ] Independent DNS protocol conformance suite and coverage-guided fuzzing
- [ ] Sustained load, latency, TCP connection exhaustion and rate-limit evaluation
- [ ] Validate full recursive / RPZ behavior with a separate staging resolver

## Resource hardening checkpoint (2026-11-11)

- [x] Configurable worker limit per TCP/UDP listener, bounded peer-state rate limiting
- [x] Deterministic token bucket tests, one live UDP denial case, 100-request concurrent UDP smoke test
- [ ] Sustained overload, TCP slow-reader/flood, cross-protocol fairness, SQLite write contention and bounded database growth
- [ ] Benchmark production-sized rate-limit defaults and ensure acceptable LAN loss/retry behavior

## RC4 retention and staging checkpoint (2026-11-11)

- [x] Bounded SQLite cleanup of expired positive and negative cache entries on writes
- [x] SQLite expiration indexes and explicitly closed initialization connection
- [x] Short-lived localhost test: 1,000 UDP queries with retries, 100 TCP queries, 300 concurrent SQLite writes
- [ ] Soak test 12–24 hours with a representative mix of cold/warm DNS, WAN failures and RPZ queries
- [ ] Compare RAM, CPU, p50/p95/p99 latency, UDP timeout rate, TCP refusals, SQLite WAL size and cache growth
- [ ] Confirm index creation cost on a backup of an actual production-size database
- [ ] Review memory and DOS behavior under many unique client IPs, long-running TCP sessions and large RPZ sets
- [ ] Confirm open-source license after verifying code provenance and ownership

## RC5 reproducible staging gate (2026-11-11)

- [x] Isolated local-only load tool with JSON report, p50/p95/p99, counts and Linux process sampling
- [x] 12-second local-only example-zone check: 480/480 requests, 0 timeouts, 0 incorrect responses
- [ ] Complete 12–24-hour run on an available staging host and save its report
- [ ] Test representative on-demand SQLite cache and RPZ policies with staging copies
- [ ] Capture cache DB, WAL and SHM sizes and integrity before/after with separately provisioned staging DB
- [ ] Inspect actual running systemd ExecStart and all drop-ins before considering migration
- [ ] Confirm operational security review, license/provenance, CI results and final release gate

**Limitations:** short localhost success is not a 12–24-hour soak or a proof
of production readiness. RC5 is a staging-tooling milestone, not a stable release.
