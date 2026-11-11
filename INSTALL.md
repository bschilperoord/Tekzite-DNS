# Tekzite DNS: Live-server deployment guide

> **Status: experimental (v0.1.0-rc5).** This repository contains a sanitized release candidate, **not a verified copy of the private live `router01` deployment**. Do not treat this guide as a production certification or replace a working resolver without staging and testing.

Tekzite DNS is a Python DNS service for local authoritative zones, with optional on-demand SQLite caching, QNAME-based RPZ filtering and additional learning features. It can run alongside an independent **Unbound validating recursive resolver**. Local clients use Tekzite's LAN IP; Unbound handles recursive lookups when configured as the system's upstream resolver. DNSSEC validation is performed by Unbound, not established by the Python service alone.

## 1. Overview

```text
LAN client -> Tekzite DNS (LAN IPv4/IPv6, UDP/TCP :53)
                 | local zone / cache answer
                 +-> system DNS -> Unbound (127.0.0.1:53)
                                       | cache hit
                                       +-> authoritative DNS on WAN when needed
```

**Important:** `--ondemand-db` uses the system resolver. To avoid forwarding loops, ensure the system resolver used by the Tekzite process points to Unbound, **not back to Tekzite**. Confirm this on the target host before enabling on-demand lookups.

The live reference network used IPv4 `192.168.25.254`, IPv6 `fd14:2291:7f99:10f2::1`, LAN interface `enp6s0`, and WAN interface `enp3s0`. These are **examples**, not universal defaults.

## 2. Prerequisites

- Ubuntu with systemd and an administratively controlled LAN
- Python 3.10+, `python3-venv`, `python3-pip`
- Unbound, `dnsutils` and optionally `tcpdump`
- A fixed LAN IPv4 address, and optionally a fixed LAN IPv6 ULA
- Firewall rules preventing the resolver from becoming an open public resolver

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip unbound dnsutils tcpdump
```

Keep the network's existing DHCP, firewall and Unbound settings backed up before changing them.

## 3. Set up the repository

Clone your copy of this repository, or use an existing checkout:

```bash
git clone https://github.com/bschilperoord/Tekzite-DNS.git
cd Tekzite-DNS
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

The current published requirement is `dnspython>=2.6,<3`. Check the pinned requirements and source whenever updating.

Start with the isolated local test from the project README:

```bash
python src/tekzite_dns.py --zone examples/zone.json --local-only --listen 127.0.0.1 --port 5533
```

In another shell:

```bash
dig @127.0.0.1 -p 5533 www.tekzite.test A
```

The demonstration zone should return the documentation address `192.0.2.42`. Do not proceed to LAN deployment until the local test works.

## 4. Configure Unbound independently

Unbound should listen on **localhost**; Tekzite listens on the dedicated LAN address(es). Ensure that no other daemon is already bound to those address/port combinations:

```bash
sudo ss -lntup | grep ':53'
sudo unbound-checkconf
```

A minimal *illustrative* Unbound fragment is:

```text
server:
    interface: 127.0.0.1
    port: 53
    access-control: 127.0.0.0/8 allow
    qname-minimisation: yes
    aggressive-nsec: yes
    prefetch: yes
```

This **does not** replace a complete working Unbound configuration. On a system using an existing Unbound install, avoid creating conflicting `interface` or `port` directives. Configure an appropriate DNSSEC trust anchor using your distribution's Unbound setup, verify network access and check:

```bash
sudo unbound-checkconf
sudo systemctl restart unbound
dig @127.0.0.1 example.com A
dig @127.0.0.1 cloudflare.com A +dnssec
dig @127.0.0.1 dnssec-failed.org A +dnssec
```

For DNSSEC, a signed positive response should normally carry `ad`, while the deliberately broken `dnssec-failed.org` should return `SERVFAIL`.

**Resolver loop warning:** Inspect `/etc/resolv.conf` and any `systemd-resolved` configuration. When Tekzite's on-demand feature uses the system resolver, it must not be pointed back at its own LAN listener. The precise solution depends on whether the host uses a stub resolver and how the application performs system DNS lookups.

## 5. Stage LAN access before port 53

The published code has a loopback-only default client ACL. A non-loopback listener requires an explicit `--allow-client` CIDR. The repo already provides a hardened localhost-only unit at [`deploy/tekzite-dns.service.example`](deploy/tekzite-dns.service.example).

First inspect the available options:

```bash
python src/tekzite_dns.py --help
```

For **LAN staging**, use a nonprivileged port such as `5533` with the real LAN address and a trusted client CIDR, adapting this example:

```bash
python src/tekzite_dns.py \
  --zone examples/zone.json \
  --local-only \
  --listen 192.168.25.254 \
  --port 5533 \
  --allow-client 192.168.25.0/24
```

Run the IPv6 listener only when your server has the corresponding address and subnet. Test both UDP and TCP from a trusted LAN client:

```bash
dig @192.168.25.254 -p 5533 www.tekzite.test A
dig @192.168.25.254 -p 5533 www.tekzite.test A +tcp
```

`--local-only` is intentionally enabled for this first test, so internet recursion is **not** expected. Only after staging should you decide whether to enable on-demand resolution, SQLite persistence, and additional RPZ or learning capabilities.

## 6. Move to a systemd service

Use the existing unit as a template:

```bash
cat deploy/tekzite-dns.service.example
```

It assumes a dedicated `tekzite-dns` user, a checkout at `/opt/tekzite-dns`, and a Python venv inside that directory. Adapt the paths to your installation. Do not blindly copy a private live unit whose home path, source filename or runtime flags differ from this public release.

Keep the default localhost-only staging service until the LAN tests, ACL, firewall and system resolver routing are verified. When using TCP/UDP port 53 as an unprivileged user, grant only the required bind capability in the unit, for example:

```ini
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

If you use `ProtectSystem=strict` and enable `--ondemand-db`, explicitly provide a writable, access-controlled state directory for SQLite. A read-only filesystem without a suitable `ReadWritePaths` or systemd state directory will prevent database writes.

After placing and adapting a unit at `/etc/systemd/system/tekzite-dns-lan.service`:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tekzite-dns-lan.service
systemctl status tekzite-dns-lan.service
sudo journalctl -u tekzite-dns-lan.service -f
```

Avoid enabling a LAN-facing service until it has passed the staged tests.

## 7. Limit DNS exposure

Allow TCP **and** UDP port 53 only from trusted LAN networks to the server's LAN interface/address. The following is an example for a host already using UFW:

```bash
sudo ufw allow in on enp6s0 from 192.168.25.0/24 to 192.168.25.254 port 53 proto udp
sudo ufw allow in on enp6s0 from 192.168.25.0/24 to 192.168.25.254 port 53 proto tcp
```

For a dual-stack network, add equivalent IPv6 rules scoped to your actual ULA range and listener address. Verify the effective rules with `sudo ufw status verbose` and preserve SSH management access. Never open recursion on the public WAN.

Advertise Tekzite's LAN address(es) to clients using your DHCP/DHCPv6 or router advertisement configuration. Do **not** change DHCP until the service is tested.

## 8. Check answers, DNSSEC and bypasses

On the server:

```bash
dig @127.0.0.1 example.com A
dig @192.168.25.254 example.com A
dig @192.168.25.254 example.com A +tcp
sudo ss -lntup | grep ':53'
```

If internet names work with Unbound but not with Tekzite, inspect Tekzite's application mode, system resolver, client ACL and logs. A `--local-only` instance is *not* intended to recurse.

Observe conventional DNS traffic from LAN clients addressed **somewhere other than Tekzite**:

```bash
sudo tcpdump -ni enp6s0 -Q in \
  '((udp dst port 53 or tcp dst port 53) and not (dst host 192.168.25.254 or dst host fd14:2291:7f99:10f2::1))'
```

Silence means no matching traffic was observed **during that capture**, not that all possible bypass methods are blocked. DNS-over-HTTPS generally travels over TCP/443 or QUIC and is not detected by this port-53 test.

WAN-side recursive traffic is normal when Unbound needs information absent from its cache:

```bash
sudo tcpdump -ni enp3s0 -Q out 'udp port 53 or tcp port 53'
```

The older `wan-dns-index.service` and automatic pin-refresh scripts are **not prerequisites for core DNS serving**. They were used for optional reporting and legacy DNS pin candidate generation.

## 9. Maintenance and limitations

- Apply security updates to Ubuntu, Python packages and Unbound.
- Keep query tracing disabled during ordinary operation if privacy matters.
- Back up the source, systemd units, zone JSON, Unbound configuration and any SQLite state before upgrades.
- Keep production DNS serving separate from experimental learning/capture features.
- Run `python -m unittest discover -s tests -v` in a test checkout before changing a live installation.
- Review [`SECURITY.md`](SECURITY.md) and [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md).
- Self-hosting reduces reliance on centralized recursive DNS providers, **but it does not provide complete anonymity**. Authoritative DNS operators can still observe recursive queries.

## Publishing status

This document explains how to **stage** the public release with Unbound and progress toward an isolated LAN deployment. It intentionally does not claim that the public `src/tekzite_dns.py` release is identical to the private `tekzite_dns_lab_v9_improved.py` running on the original server. A production-reproducible installation guide requires reconciling the live source, actual systemd configuration, DNS upstream selection, and long-run tests.

**Tekzite DNS: Your DNS. Your Network. Your Privacy.**
