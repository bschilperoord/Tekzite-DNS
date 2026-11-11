# Tekzite DNS

**Privacy-focused, Python-based DNS server with local authoritative resolution, optional on-demand learning, caching, RPZ filtering and configurable client access controls.**

> **Status: v0.1.0-rc5 (experimental).** Not yet validated for unattended production deployment. Run on a staging host first.

## Features

- Local authoritative DNS records and LAN-specific name resolution
- Optional on-demand resolution and database-backed caching
- RPZ-based filtering
- Configurable client network allowlists
- UDP and TCP DNS support
- EDNS and malformed-packet validation
- Optional query rate limiting and configurable worker limits
- SQLite expiry cleanup and concurrency testing

## Release status

The RC5 candidate passed 36 automated tests and short local UDP/TCP smoke tests. A 12–24-hour staging soak test, production-sized database benchmarks, recursive/RPZ interoperability testing and independent security review remain outstanding.

**Do not expose an open DNS resolver to the Internet.** Restrict clients through both the program allowlist and host firewall.

## Source distribution

The complete RC5 source tree is being prepared for import into this repository. Until that upload is complete, this README is only the project landing page and **does not represent a complete installation**. The package includes code, tests, CI and a staging soak-test tool.

## Security

Please avoid posting vulnerable configurations, credentials, private zones or live resolver addresses in public issues. No stability or security guarantee is made for this experimental release.

## License

No open-source license has been selected yet. All rights reserved unless a license is added by the copyright holder.
