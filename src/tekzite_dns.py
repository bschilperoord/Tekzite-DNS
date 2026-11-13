#!/usr/bin/env python3
"""Authoritative DNS with optional active and passive WAN learning. Python 3.10+.

Run the demo zone on loopback: python3 tekzite_dns_lab.py
Export an editable zone: python3 tekzite_dns_lab.py --example-zone > zone.json
Export a private TLD and child zone: python3 tekzite_dns_lab.py --example-private-zones > private-zones.json
Serve it: python3 tekzite_dns_lab.py --zone zone.json
Load additional JSON zones: python3 tekzite_dns_lab.py --zone zone.json --zone-dir zones
With --zone-dir, automatic downloads export separate delegation and zone files.
Download public TLD snapshots while serving: python3 tekzite_dns_lab.py --auto-download-tlds
Serve only local data: python3 tekzite_dns_lab.py --local-only --zone zone.json
Resolve and learn: python3 tekzite_dns_lab.py --resolve-wan --trace
Repeat --listen to serve more than one IPv4 or IPv6 address on the same port.
Observe WAN DNS: sudo python3 tekzite_dns_lab.py --learn-wan WAN_IFACE
Query: dig @127.0.0.1 -p 5533 example.com A
Read learned data without a WAN lookup: dig @127.0.0.1 -p 5533 example.com A +norecurse

Active learning runs nonrecursive dig against numeric TLD and domain
nameserver addresses. It starts from a local root snapshot and keeps A and
AAAA answers in memory through their DNS TTLs. DNS root servers are blocked.
Passive learning uses a Linux packet socket and CAP_NET_RAW
to observe plain UDP/53 traffic on the specified interface.
Configured local zones take precedence over learned answers.
"""

import argparse
import ctypes
import hashlib
import ipaddress
import json
import logging
import math
import random
import re
import shutil
import socket
import ssl
import socketserver
import struct
import subprocess
import tempfile
import threading
import sqlite3
import time
from collections import OrderedDict
from contextlib import ExitStack, closing
from dataclasses import dataclass, replace
from functools import partial
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, OPT, CAA = 1, 2, 5, 6, 12, 15, 16, 28, 33, 41, 257
DS = 43
QR, AA, TC, RD, RA = 0x8000, 0x0400, 0x0200, 0x0100, 0x0080
OK, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED, BADVERS = 0, 1, 2, 3, 4, 5, 16
IN, ANY = 1, 255
UDP_SIZE = 1232
ROOT = ()
# IANA root server addresses are blocked as destinations.
ROOT_SERVERS = (
    "198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13",
    "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
    "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
    "202.12.27.33",
    "2001:503:ba3e::2:30", "2801:1b8:10::b", "2001:500:2::c", "2001:500:2d::d",
    "2001:500:a8::e", "2001:500:2f::f", "2001:500:12::d0d", "2001:500:1::53",
    "2001:7fe::53", "2001:503:c27::2:30", "2001:7fd::1", "2001:500:9f::42",
    "2001:dc3::35",
)
# Registry endpoints verified against IANA's delegation records. Each is
# checked with an authoritative apex NS query before a route is saved.
VERISIGN_BOOTSTRAP = {
    (b"a", b"gtld-servers", b"net"): ("192.5.6.30", "2001:503:a83e::2:30"),
    (b"b", b"gtld-servers", b"net"): ("192.33.14.30", "2001:503:231d::2:30"),
}
TLD_BOOTSTRAP = {
    (b"com",): VERISIGN_BOOTSTRAP,
    (b"net",): VERISIGN_BOOTSTRAP,
    (b"org",): {
        (b"b2", b"org", b"afilias-nst", b"org"): ("199.249.120.1", "2001:500:48::1"),
        (b"v0n0", b"pir-ns", b"org"): ("199.19.56.1", "2001:500:e::1"),
    },
    (b"network",): {
        (b"v0n0", b"nic", b"network"): ("65.22.32.36", "2a01:8840:22::36"),
        (b"v0n1", b"nic", b"network"): ("65.22.33.36", "2a01:8840:23::36"),
    },
}
SINGLE_NAME = {NS, 3, 4, CNAME, 7, 8, 9, PTR}
MAX_TTL = 2**31 - 1
TYPES = {"A": A, "AAAA": AAAA, "CNAME": CNAME, "NS": NS, "PTR": PTR,
         "MX": MX, "TXT": TXT, "SRV": SRV, "CAA": CAA}
LABEL = re.compile(rb"[a-z0-9_-]{1,63}")
LOCAL_SUFFIXES = ((b"home", b"arpa"), (b"local",), (b"localhost",), (b"test",),
                  (b"invalid",), (b"example",), (b"onion",), (b"internal",))
EXAMPLE_ZONE = {
    "origin": "tekzite.test.",
    "ttl": 300,
    "soa": {"primary": "ns1", "mailbox": "hostmaster", "serial": 1,
            "refresh": 3600, "retry": 600, "expire": 86400, "minimum": 60},
    "records": [
        {"name": "@", "type": "NS", "value": "ns1"},
        {"name": "ns1", "type": "A", "value": "192.0.2.53"},
        {"name": "www", "type": "A", "value": "192.0.2.42"},
        {"name": "alias", "type": "CNAME", "value": "www"},
    ],
}
PRIVATE_EXAMPLE_ZONES = [
    {
        "origin": "internal.",
        "ttl": 300,
        "soa": EXAMPLE_ZONE["soa"],
        "records": [
            {"name": "@", "type": "NS", "value": "ns1"},
            {"name": "ns1", "type": "A", "value": "192.0.2.53"},
            {"name": "ns1", "type": "AAAA", "value": "2001:db8::53"},
            {"name": "tekzite", "type": "NS", "value": "ns1.tekzite"},
            {"name": "ns1.tekzite", "type": "A", "value": "192.0.2.53"},
            {"name": "ns1.tekzite", "type": "AAAA", "value": "2001:db8::53"},
        ],
    },
    {
        "origin": "tekzite.internal.",
        "ttl": 300,
        "soa": EXAMPLE_ZONE["soa"],
        "records": [
            {"name": "@", "type": "NS", "value": "ns1"},
            {"name": "ns1", "type": "A", "value": "192.0.2.53"},
            {"name": "ns1", "type": "AAAA", "value": "2001:db8::53"},
            {"name": "router", "type": "A", "value": "192.0.2.53"},
            {"name": "router", "type": "AAAA", "value": "2001:db8::53"},
        ],
    },
]
TLD_DOWNLOADS = {
    "tlds-alpha-by-domain.txt": (
        "https://data.iana.org/TLD/tlds-alpha-by-domain.txt",
        ("104.18.24.232", "104.18.25.232", "2606:4700::6812:18e8", "2606:4700::6812:19e8"),
        256 * 1024,
    ),
    "root.zone": (
        "https://www.internic.net/domain/root.zone",
        ("192.0.46.9", "2620:0:2830:200::b:9"),
        8 * 1024 * 1024,
    ),
}
TLD_REFRESH_SECONDS = 86400
TLD_RETRY_SECONDS = 900
ZONE_REFRESH_SECONDS = 900


class WireError(ValueError):
    pass


class ResolutionError(Exception):
    pass


def read_name(packet, offset):
    labels, end, visited, size = [], None, set(), 1
    while offset < len(packet):
        if offset in visited:
            break
        visited.add(offset)
        length = packet[offset]
        if length == 0:
            return tuple(labels), offset + 1 if end is None else end
        if length & 0xC0 == 0xC0 and offset + 1 < len(packet):
            target = ((length & 0x3F) << 8) | packet[offset + 1]
            if target >= offset:
                break
            if end is None:
                end = offset + 2
            offset = target
            continue
        if length > 63 or offset + 1 + length > len(packet):
            break
        size += length + 1
        if size > 255:
            break
        labels.append(packet[offset + 1 : offset + 1 + length])
        offset += 1 + length
    raise WireError("invalid DNS name")


def name_wire(name):
    return b"".join(bytes([len(label)]) + label for label in name) + b"\0"


def lower_name(name):
    return tuple(label.lower() for label in name)


def under(name, zone):
    return len(name) >= len(zone) and (not zone or name[-len(zone):] == zone)


def wan_name(name):
    return (len(name) >= 2 and all(LABEL.fullmatch(label) for label in name)
            and not any(under(name, suffix) for suffix in LOCAL_SUFFIXES))


def name_text(name):
    return b".".join(name).decode("ascii", errors="backslashreplace") + "."


@dataclass(frozen=True)
class Question:
    name: tuple[bytes, ...]
    kind: int
    cls: int = IN

    def wire(self):
        return name_wire(self.name) + struct.pack("!HH", self.kind, self.cls)

    def canonical(self):
        return replace(self, name=lower_name(self.name))


@dataclass(frozen=True)
class Record:
    name: tuple[bytes, ...]
    kind: int
    cls: int
    ttl: int
    data: bytes

    def wire(self):
        return (name_wire(self.name)
                + struct.pack("!HHIH", self.kind, self.cls, self.ttl, len(self.data))
                + self.data)

    def target(self):
        return lower_name(read_name(self.data, 0)[0])


@dataclass(frozen=True)
class Reply:
    code: int
    answers: tuple[Record, ...] = ()
    authority: tuple[Record, ...] = ()
    additional: tuple[Record, ...] = ()
    authoritative: bool = False


def read_question(packet):
    name, offset = read_name(packet, 12)
    if offset + 4 > len(packet):
        raise WireError("incomplete DNS question")
    return Question(name, *struct.unpack_from("!HH", packet, offset)), offset + 4


def record_data(packet, start, end, kind):
    # Expand legacy compressed RDATA before moving it into a new message.
    if kind not in SINGLE_NAME and kind not in (SOA, 14, 15):
        return packet[start:end]
    prefix = 2 if kind == 15 else 0  # MX preference
    offset = start + prefix
    data = packet[start:offset]
    for _ in range(2 if kind in (SOA, 14) else 1):
        name, offset = read_name(packet, offset)
        data += name_wire(name)
    tail = 20 if kind == SOA else 0
    if offset + tail != end:
        raise WireError("invalid name record length")
    return data + packet[offset:end]


def read_sections(packet, offset, counts):
    sections = []
    expanded_size = offset
    for count in counts:
        records = []
        for _ in range(count):
            name, offset = read_name(packet, offset)
            if offset + 10 > len(packet):
                raise WireError("incomplete resource record")
            kind, cls, ttl, length = struct.unpack_from("!HHIH", packet, offset)
            start = offset + 10
            offset = start + length
            if offset > len(packet):
                raise WireError("incomplete record data")
            if kind != OPT and ttl > MAX_TTL:
                ttl = 0
            data = record_data(packet, start, offset, kind)
            expanded_size += sum(len(label) + 1 for label in name) + 11 + len(data)
            if expanded_size > 65535:
                raise WireError("expanded DNS message is too large")
            records.append(Record(lower_name(name), kind, cls, ttl, data))
        sections.append(tuple(records))
    if offset != len(packet):
        raise WireError("trailing DNS message data")
    return sections


def validate_edns_options(data):
    """Validate the framing of EDNS(0) options without interpreting their payloads.

    Unknown options remain permitted as required for EDNS extensibility.
    """
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise WireError("truncated EDNS option header")
        _code, length = struct.unpack_from("!HH", data, offset)
        offset += 4
        if length > len(data) - offset:
            raise WireError("truncated EDNS option payload")
        offset += length


def receive_exact(connection, size, deadline):
    data = bytearray()
    while len(data) < size:
        connection.settimeout(time_left(deadline))
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise EOFError
        data.extend(chunk)
    return bytes(data)


def time_left(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("DNS deadline expired")
    return remaining


def domain(text, origin=ROOT):
    if text == "@":
        return origin
    if text == ".":
        return ROOT
    if not isinstance(text, str) or not text:
        raise ValueError("expected a DNS name")
    absolute = text.endswith(".")
    raw = text[:-1] if absolute else text
    labels = tuple(label.encode("idna").lower() for label in raw.split("."))
    if not all(LABEL.fullmatch(label) or (i == 0 and label == b"*")
               for i, label in enumerate(labels)):
        raise ValueError(f"invalid DNS name {text!r}")
    name = labels if absolute else labels + origin
    if len(name_wire(name)) > 255:
        raise ValueError(f"DNS name is too long: {text!r}")
    return name


def integer(value, limit):
    if type(value) is not int or not 0 <= value <= limit:
        raise ValueError(f"expected an integer from 0 to {limit}, got {value!r}")
    return value


def zone_data(kind, value, origin):
    if kind in (A, AAAA):
        address = ipaddress.ip_address(value)
        if address.version != (4 if kind == A else 6):
            raise ValueError(f"address family does not match record type: {value!r}")
        return address.packed
    if kind in (NS, PTR, CNAME):
        return name_wire(domain(value, origin))
    if kind == TXT:
        encoded = value.encode("utf-8")
        if not encoded:
            return b"\0"
        return b"".join(bytes([len(encoded[i:i + 255])]) + encoded[i:i + 255]
                        for i in range(0, len(encoded), 255))
    if kind == CAA:
        tag = value["tag"].lower().encode("ascii")
        if not re.fullmatch(rb"[a-z0-9]{1,15}", tag):
            raise ValueError("invalid CAA tag")
        return bytes([integer(value["flags"], 255), len(tag)]) + tag + value["value"].encode("utf-8")
    keys = ("preference",) if kind == MX else ("priority", "weight", "port")
    return (b"".join(struct.pack("!H", integer(value[key], 65535)) for key in keys)
            + name_wire(domain(value["target"], origin)))


class Zone:
    def __init__(self, config):
        self.origin = domain(config["origin"])
        ttl = integer(config.get("ttl", 300), MAX_TTL)
        fields = config["soa"]
        soa_data = name_wire(domain(fields["primary"], self.origin))
        soa_data += name_wire(domain(fields["mailbox"], self.origin))
        for key in ("serial", "refresh", "retry", "expire", "minimum"):
            soa_data += struct.pack("!I", integer(fields[key], 2**32 - 1 if key == "serial" else MAX_TTL))
        soa = Record(self.origin, SOA, IN, ttl, soa_data)
        self.negative_soa = replace(soa, ttl=min(ttl, fields["minimum"]))
        self.nodes = {self.origin: {SOA: [soa]}}
        for item in config["records"]:
            owner = domain(item["name"], self.origin)
            if not under(owner, self.origin):
                raise ValueError(f"{item['name']!r} lies outside the zone")
            kind = TYPES[item["type"].upper()]
            record_ttl = integer(item.get("ttl", ttl), MAX_TTL)
            data = zone_data(kind, item["value"], self.origin)
            if len(data) > 65000:
                raise ValueError(f"record data too large at {item['name']!r}")
            rrset = self.nodes.setdefault(owner, {}).setdefault(kind, [])
            if rrset and rrset[0].ttl != record_ttl:
                raise ValueError(f"record set at {item['name']!r} must use one TTL")
            if not any(rr.data == data for rr in rrset):
                rrset.append(Record(owner, kind, IN, record_ttl, data))
        if NS not in self.nodes[self.origin]:
            raise ValueError("the zone needs an apex NS record")
        for owner, sets in tuple(self.nodes.items()):
            if CNAME in sets and (len(sets) != 1 or len(sets[CNAME]) != 1):
                raise ValueError(f"CNAME must be the only record at {name_text(owner)}")
            if NS in sets and owner[:1] == (b"*",):
                raise ValueError("wildcard NS records are unsupported")
            for i in range(1, len(owner) - len(self.origin)):
                self.nodes.setdefault(owner[i:], {})

    def cut(self, name):
        for length in range(len(self.origin) + 1, len(name) + 1):
            suffix = name[-length:]
            if NS in self.nodes.get(suffix, {}):
                return suffix
        return None

    def referral(self, cut):
        nameservers = tuple(self.nodes[cut][NS])
        glue = []
        for rr in nameservers:
            host = rr.target()
            if under(host, cut):
                for kind in (A, AAAA):
                    glue.extend(self.nodes.get(host, {}).get(kind, ()))
        return Reply(OK, authority=nameservers, additional=tuple(glue))

    def node(self, name):
        if name in self.nodes:
            return self.nodes[name]
        for i in range(1, len(name) - len(self.origin) + 1):
            ancestor = name[i:]
            if ancestor in self.nodes:
                return self.nodes.get((b"*",) + ancestor)
        return None

    def answer(self, question):
        name, kind = question.name, question.kind
        cut = self.cut(name)
        if cut:
            # The parent side owns the DS lookup. These zones are unsigned.
            if name == cut and kind == DS:
                return Reply(OK, authority=(self.negative_soa,), authoritative=True)
            return self.referral(cut)
        aliases, seen = [], set()
        while name not in seen and len(seen) < 16:
            seen.add(name)
            node = self.node(name)
            if node is None:
                return Reply(NXDOMAIN, tuple(aliases), (self.negative_soa,), authoritative=True)
            rrset = node.get(kind, ())
            if kind == ANY and node:
                rrset = next(iter(node.values()))
            if rrset:
                answers = tuple(aliases) + tuple(replace(rr, name=name) for rr in rrset)
                return Reply(OK, answers, authoritative=True)
            if CNAME not in node:
                return Reply(OK, tuple(aliases), (self.negative_soa,), authoritative=True)
            alias = replace(node[CNAME][0], name=name)
            aliases.append(alias)
            name = alias.target()
            if not under(name, self.origin) or self.cut(name):
                return Reply(OK, tuple(aliases), authoritative=True)
        return Reply(SERVFAIL)


def public_addresses(records, owner, kind):
    length = 4 if kind == A else 16
    addresses = {}
    for rr in records:
        if (rr.name, rr.kind, rr.cls, len(rr.data)) == (owner, kind, IN, length):
            address = ipaddress.ip_address(rr.data)
            if public_ip(address):
                address = str(address)
                addresses[address] = min(rr.ttl, addresses.get(address, rr.ttl))
    return addresses


def public_ip(address):
    return (address.is_global and not address.is_multicast
            and getattr(address, "ipv4_mapped", None) is None)


def closest_soa(records, name):
    return max((rr for rr in records if rr.kind == SOA and rr.cls == IN
                and under(name, rr.name)), key=lambda rr: len(rr.name), default=None)


def registry_snapshot(path):
    """Read NS and address records from a local root-zone master file."""
    with path.open(encoding="ascii") as zone_file:
        return read_registry_snapshot(zone_file)


def read_registry_snapshot(zone_file):
    origin, owner = ROOT, None
    pending, depth = [], 0
    ns, addresses = {}, {}
    root_soa = False
    for raw in zone_file:
        line = raw.split(";", 1)[0]
        fields = line.replace("(", " ").replace(")", " ").split()
        if not fields and not line.strip():
            continue
        if not pending:
            inherited_owner = line[0].isspace()
        pending.extend(fields)
        depth += line.count("(") - line.count(")")
        if depth < 0:
            raise ValueError("unbalanced parentheses in bootstrap snapshot")
        if depth or not pending:
            continue
        fields, pending = pending, []
        if fields[0].startswith("$"):
            directive = fields[0].upper()
            if directive == "$ORIGIN" and len(fields) == 2:
                origin = domain(fields[1], origin)
            elif directive != "$TTL" or len(fields) != 2:
                raise ValueError(f"unsupported bootstrap snapshot directive {directive}")
            continue
        if not inherited_owner:
            owner = domain(fields.pop(0), origin)
        if owner is None:
            raise ValueError("bootstrap snapshot record has no owner")
        cls = "IN"
        while fields:
            token = fields[0].upper()
            if token in ("IN", "CH", "HS"):
                cls = fields.pop(0).upper()
            elif re.fullmatch(r"(?:[0-9]+[WDHMS]?)+", token):
                fields.pop(0)
            else:
                break
        if not fields or cls != "IN":
            continue
        kind, *data = fields
        kind = kind.upper()
        if kind == "SOA" and owner == ROOT:
            root_soa = True
        elif kind == "NS" and len(owner) <= 1 and len(data) == 1:
            ns.setdefault(owner, set()).add(domain(data[0], origin))
        elif kind in ("A", "AAAA") and len(data) == 1:
            address = ipaddress.ip_address(data[0])
            if address.version == (4 if kind == "A" else 6) and public_ip(address):
                addresses.setdefault(owner, set()).add(str(address))
    if depth or not root_soa or ROOT not in ns or not all((tld,) in ns for tld in (b"com", b"net", b"org")):
        raise ValueError("expected a complete root-zone snapshot with apex SOA and TLD delegations")
    roots = set(ROOT_SERVERS)
    for host in ns.pop(ROOT):
        roots.update(addresses.get(host, ()))
    return {
        zone: {host: addresses.get(host, set()) - roots for host in hosts}
        for zone, hosts in ns.items()
    }, roots


class ResolverState:
    def __init__(self, snapshot=None):
        self.snapshot = snapshot
        self.signature = None
        self.registry = {}
        self.roots = set(ROOT_SERVERS)
        self.referrals = OrderedDict()
        self.lock = threading.Lock()

    def root_addresses(self):
        with self.lock:
            if self.snapshot is not None:
                try:
                    stat = self.snapshot.stat()
                    signature = (stat.st_ino, stat.st_mtime_ns, stat.st_size)
                    if signature != self.signature:
                        self.signature = signature
                        self.registry, self.roots = registry_snapshot(self.snapshot)
                        logging.info("loaded TLD hints for %d zones from %s", len(self.registry), self.snapshot)
                except FileNotFoundError:
                    pass
                except (OSError, ValueError) as error:
                    logging.warning("could not load TLD hints from %s: %s", self.snapshot, error)
            return self.roots

    def hints(self, zone):
        with self.lock:
            return self.registry.get(zone, {})

    def remember(self, zone, addresses, ns_expires):
        now = time.monotonic()
        expiry = {ip: min(now + ttl, ns_expires) for ip, ttl in addresses.items()
                  if ttl > 0 and ns_expires > now}
        if not expiry:
            return
        with self.lock:
            cached = {ip: until for ip, until in self.referrals.get(zone, {}).items() if until > now}
            cached.update(expiry)
            self.referrals[zone] = dict(list(cached.items())[-32:])
            self.referrals.move_to_end(zone)
            if len(self.referrals) > 2048:
                self.referrals.popitem(last=False)

    def routes(self, name):
        now = time.monotonic()
        routes = []
        with self.lock:
            for index in range(len(name)):
                zone = name[index:]
                addresses = [ip for ip, until in self.referrals.get(zone, {}).items() if until > now]
                if addresses:
                    routes.append((zone, sorted(addresses, key=lambda ip: ":" in ip)))
        return routes


class IterativeLookup:
    def __init__(self, timeout, referrals):
        self.deadline = time.monotonic() + timeout
        self.queries_left = 64
        self.active = set()
        self.referrals = referrals
        self.queried = set()
        self.blocked_roots = set(ROOT_SERVERS)
        self.blocked_roots.update(referrals.root_addresses())
        self.bootstrap_attempted = set()

    def resolve(self, question):
        if not wan_name(question.name):
            raise ResolutionError("name is outside WAN lookup scope")
        if question in self.active or len(self.active) >= 16:
            raise ResolutionError("cyclic dependency or too many aliases")
        self.active.add(question)
        try:
            for zone, addresses in self.referrals.routes(question.name):
                logging.debug("using saved referral %s for %s", name_text(zone), name_text(question.name))
                try:
                    return self.ask(question, zone, addresses)
                except ResolutionError:
                    continue
            tld = question.name[-1:]
            if tld not in self.bootstrap_attempted:
                self.bootstrap_attempted.add(tld)
                addresses = self.bootstrap(tld)
                if addresses:
                    return self.ask(question, tld, addresses)
            raise ResolutionError(f"no usable registry route for {name_text(question.name)}; root disabled")
        finally:
            self.active.remove(question)

    def bootstrap(self, zone):
        seeds = self.referrals.hints(zone) or TLD_BOOTSTRAP.get(zone, {})
        endpoints = {(host, address): float("inf")
                     for host, addresses in seeds.items() for address in addresses}
        # Out-of-zone nameservers can be resolved using another TLD's routes.
        for host in seeds if not endpoints else ():
            if not under(host, zone):
                for kind in (A, AAAA):
                    try:
                        reply = self.resolve(Question(host, kind))
                    except ResolutionError:
                        continue
                    if reply.answers:
                        expiry = time.monotonic() + min(rr.ttl for rr in reply.answers)
                        endpoints.update({(host, ip): expiry for ip in public_addresses(reply.answers, host, kind)})
        for host, address in sorted(endpoints, key=lambda endpoint: ":" in endpoint[1]):
            if address in self.blocked_roots:
                continue
            if not self.queries_left or time.monotonic() >= self.deadline:
                break
            self.queries_left -= 1
            logging.debug("checking registry referral %s via %s", name_text(zone), address)
            try:
                reply = dig_lookup(Question(zone, NS), address,
                                 min(self.deadline, time.monotonic() + 1.5))
            except (OSError, ValueError, struct.error, subprocess.SubprocessError) as error:
                logging.debug("registry referral check via %s failed: %s", address, error)
                continue
            if not reply.authoritative or reply.code != OK:
                continue
            records = [rr for rr in reply.answers if (rr.name, rr.kind, rr.cls) == (zone, NS, IN)]
            nameservers = {rr.target() for rr in records}
            if host not in nameservers:
                continue
            ttl = min(rr.ttl for rr in records)
            now = time.monotonic()
            addresses = {ip: max(0, int(min(expiry, now + ttl) - now))
                         for (ns_name, ip), expiry in endpoints.items()
                         if ns_name in nameservers and ip not in self.blocked_roots}
            self.referrals.remember(zone, addresses, now + ttl)
            logging.debug("bootstrapped referral %s via %s ttl=%d", name_text(zone), address, ttl)
            return sorted(addresses, key=lambda ip: (ip != address, ":" in ip))
        return ()

    def ask(self, question, zone, servers):
        for server in dict.fromkeys(servers):
            key = (question, zone, server)
            if server in self.blocked_roots or key in self.queried:
                continue
            self.queried.add(key)
            if not self.queries_left or time.monotonic() >= self.deadline:
                break
            self.queries_left -= 1
            logging.debug("iterative %s type=%d via %s for %s",
                          name_text(question.name), question.kind, server, name_text(zone))
            try:
                reply = dig_lookup(question, server,
                                 min(self.deadline, time.monotonic() + 1.5))
                if reply.code not in (OK, NXDOMAIN):
                    logging.debug("iterative %s returned DNS status %d", server, reply.code)
                    continue
                if reply.authoritative:
                    return self.answer(question, zone, reply)
                if reply.code == OK:
                    return self.follow(question, zone, reply)
            except (OSError, ValueError, struct.error, subprocess.SubprocessError, ResolutionError) as error:
                logging.debug("iterative %s for %s failed: %s",
                              server, name_text(question.name), str(error) or type(error).__name__)
                continue
        raise ResolutionError(f"no usable answer for {name_text(question.name)}")

    def answer(self, question, zone, reply):
        owned = tuple(rr for rr in reply.answers
                      if rr.name == question.name and rr.cls == IN)
        length = 4 if question.kind == A else 16
        records = tuple(rr for rr in owned if rr.kind == question.kind and len(rr.data) == length)
        if records and reply.code == OK:
            return Reply(OK, records)
        alias = next((rr for rr in owned if rr.kind == CNAME), None)
        if alias:
            resolved = self.resolve(replace(question, name=alias.target()))
            return Reply(resolved.code, (alias,) + resolved.answers, resolved.authority)
        soa = closest_soa(reply.authority, question.name)
        if soa and under(soa.name, zone):
            minimum, = struct.unpack("!I", soa.data[-4:])
            return Reply(reply.code, authority=(replace(soa, ttl=min(soa.ttl, minimum)),))
        raise ResolutionError("no usable authoritative answer")

    def follow(self, question, zone, reply):
        delegations = [rr for rr in reply.authority if rr.kind == NS and rr.cls == IN
                       and len(rr.name) > len(zone) and under(rr.name, zone)
                       and under(question.name, rr.name)]
        if not delegations:
            raise ResolutionError("no usable referral")
        child = max((rr.name for rr in delegations), key=len)
        delegation = [rr for rr in delegations if rr.name == child]
        ns_expires = time.monotonic() + min(rr.ttl for rr in delegation)
        hosts = list(dict.fromkeys(rr.target() for rr in delegation))
        random.shuffle(hosts)

        # The parent can supply glue for listed servers in the child or a
        # sibling zone. Prefer child glue. Addresses outside the parent still
        # require an independent lookup.
        hosts.sort(key=lambda host: not under(host, child))
        glue_hosts = [host for host in hosts if under(host, zone)]
        glue = {
            kind: {address: ttl for host in glue_hosts
                   for address, ttl in public_addresses(reply.additional, host, kind).items()}
            for kind in (A, AAAA)
        }
        self.referrals.remember(child, {**glue[A], **glue[AAAA]}, ns_expires)
        for addresses in glue.values():
            if addresses:
                try:
                    return self.ask(question, child, addresses)
                except ResolutionError:
                    pass

        # Resolve out-of-zone names independently and prefer IPv4 transport.
        hosts.sort(key=lambda host: under(host, child))
        for kind in (A, AAAA):
            for host in hosts:
                if not self.queries_left or time.monotonic() >= self.deadline:
                    raise ResolutionError("referral lookup budget expired")
                if under(host, child) and public_addresses(reply.additional, host, kind):
                    continue
                try:
                    resolved = self.resolve(Question(host, kind))
                    owner = host
                    for rr in resolved.answers:
                        if rr.name == owner and rr.kind == CNAME:
                            owner = rr.target()
                    addresses = public_addresses(resolved.answers, owner, kind)
                    if addresses:
                        ttl = min(rr.ttl for rr in resolved.answers)
                        self.referrals.remember(child, dict.fromkeys(addresses, ttl), ns_expires)
                        return self.ask(question, child, addresses)
                except ResolutionError:
                    continue
        raise ResolutionError("no reachable nameserver for referral")


def address_chain(question, answers):
    owner, ttl = question.name, MAX_TTL
    seen = set()
    length = 4 if question.kind == A else 16
    for _ in range(16):
        if owner in seen:
            break
        seen.add(owner)
        own = [rr for rr in answers if rr.name == owner and rr.cls == IN]
        addresses = [rr for rr in own if rr.kind == question.kind and len(rr.data) == length]
        aliases = {rr.target(): rr.ttl for rr in own if rr.kind == CNAME}
        if addresses and not aliases:
            ttl = min(ttl, *(rr.ttl for rr in addresses))
            return tuple(dict.fromkeys(rr.data for rr in addresses)), ttl, None
        if not own and owner != question.name:
            return (), ttl, owner
        if len(aliases) != 1 or addresses:
            break
        owner, alias_ttl = next(iter(aliases.items()))
        ttl = min(ttl, alias_ttl)
    return (), 0, None


def dig_lookup(question, server, deadline):
    kind = {A: "A", AAAA: "AAAA", NS: "NS"}[question.kind]
    name = name_text(question.name)
    logging.debug("dig @%s %s %s +norecurse", server, name, kind)
    result = subprocess.run(
        ["dig", "-r", f"@{server}", "-q", name, "-t", kind, "+norecurse",
         "+time=1", "+tries=1", "+bufsize=1232", "+noall", "+comments",
         "+answer", "+authority", "+additional", "+nomultiline"],
        capture_output=True, text=True, encoding="ascii", errors="replace",
        timeout=time_left(deadline), check=True,
    )
    header = re.search(r"^;; ->>HEADER<<- opcode: QUERY, status: ([A-Z0-9]+),", result.stdout, re.M)
    if not header:
        raise WireError("missing DNS response header from dig")
    codes = {"NOERROR": OK, "NXDOMAIN": NXDOMAIN, "REFUSED": REFUSED,
             "FORMERR": FORMERR, "NOTIMP": NOTIMP, "SERVFAIL": SERVFAIL}
    code = codes.get(header[1], SERVFAIL)
    if code not in (OK, NXDOMAIN):
        return Reply(code)
    flags = re.search(r"^;; flags: ([^;]*);", result.stdout, re.M)
    authoritative = flags is not None and "aa" in flags[1].split()
    answers, authority, additional = [], [], []
    section = None
    for line in result.stdout.splitlines():
        if line.startswith(";; ") and line.endswith(" SECTION:"):
            section = line
        fields = line.strip().split(maxsplit=4)
        if len(fields) != 5 or fields[0].startswith(";") or fields[2] != "IN":
            continue
        owner, ttl, _, kind_text, value = fields
        if section == ";; ANSWER SECTION:" and kind_text in ("A", "AAAA", "CNAME", "NS"):
            target = answers
        elif section == ";; AUTHORITY SECTION:" and kind_text in ("NS", "SOA"):
            target = authority
        elif section == ";; ADDITIONAL SECTION:" and kind_text in ("A", "AAAA"):
            target = additional
        else:
            continue
        if kind_text == "SOA":
            primary, mailbox, *numbers = value.split()
            data = name_wire(domain(primary)) + name_wire(domain(mailbox))
            data += struct.pack("!5I", *(integer(int(number), 2**32 - 1) for number in numbers))
            rrtype = SOA
        else:
            rrtype = TYPES[kind_text]
            data = zone_data(rrtype, value, ROOT)
        target.append(Record(domain(owner), rrtype, IN, integer(int(ttl), MAX_TTL), data))
    return Reply(code, tuple(answers), tuple(authority), tuple(additional), authoritative)


class LearnedRecords:
    def __init__(self, capacity=4096):
        self.records = OrderedDict()
        self.capacity = capacity
        self.lock = threading.Lock()

    def publish(self, question, ttl, now, *, addresses=(), target=None):
        with self.lock:
            if not ttl:
                self.records.pop(question, None)
                return
            self.records[question] = (now + ttl, addresses, target)
            self.records.move_to_end(question)
            if len(self.records) > self.capacity:
                self.records.popitem(last=False)
        logging.debug("learned %s type=%d %s ttl=%d", name_text(question.name),
                      question.kind, name_text(target) if target is not None
                      else f"{len(addresses)} address(es)", ttl)

    def answer(self, question, now):
        with self.lock:
            current, deadline = question, now + MAX_TTL
            for _ in range(16):
                entry = self.records.get(current)
                if entry is None:
                    break
                expires, addresses, target = entry
                if now >= expires:
                    del self.records[current]
                    break
                deadline = min(deadline, expires)
                if target is None:
                    return tuple(Record(question.name, question.kind, IN, int(deadline - now), data)
                                 for data in addresses)
                current = replace(current, name=target)
        return ()


def udp_packet(packet):
    if len(packet) < 20:
        return None
    version = packet[0] >> 4
    if version == 4:
        offset = (packet[0] & 15) * 4
        end, = struct.unpack_from("!H", packet, 2)
        fragments, = struct.unpack_from("!H", packet, 6)
        if offset < 20 or fragments & 0x3FFF or packet[9] != socket.IPPROTO_UDP:
            return None
        source, destination = packet[12:16], packet[16:20]
    elif version == 6 and len(packet) >= 40:
        if packet[6] != socket.IPPROTO_UDP:
            return None
        offset = 40
        end = offset + struct.unpack_from("!H", packet, 4)[0]
        source, destination = packet[8:24], packet[24:40]
    else:
        return None
    if not offset + 8 <= end <= len(packet):
        return None
    src_port, dst_port, length = struct.unpack_from("!HHH", packet, offset)
    if not 8 <= length <= end - offset:
        return None
    return (source, src_port), (destination, dst_port), packet[offset + 8:offset + length]


class WanLearner:
    def __init__(self, records):
        self.records = records
        self.pending = OrderedDict()

    def observe(self, packet, outgoing, now):
        datagram = udp_packet(packet)
        if datagram is None:
            return
        source, destination, dns = datagram
        if (destination if outgoing else source)[1] != 53 or len(dns) < 12:
            return
        txid, flags, qd, an, ns, ar = struct.unpack_from("!6H", dns)
        if qd != 1 or flags & 0x7800 or bool(flags & QR) == outgoing:
            return
        try:
            question, offset = read_question(dns)
            question = question.canonical()
            if (question.cls != IN or question.kind not in (A, AAAA)
                    or not question.name or not all(LABEL.fullmatch(label) for label in question.name)):
                return
            if outgoing:
                key = (source, destination, txid, question)
                self.pending[key] = now
                self.pending.move_to_end(key)
                if len(self.pending) > 4096:
                    self.pending.popitem(last=False)
                return
            key = (destination, source, txid, question)
            sent = self.pending.get(key)
            if sent is None or now - sent > 10 or flags & (TC | 15) or not an:
                return
            answers, _, additional = read_sections(dns, offset, (an, ns, ar))
            if any(rr.kind == OPT and rr.ttl >> 24 for rr in additional):
                return
            self.learn(question, answers, now)
            self.pending.pop(key, None)
        except WireError:
            return

    def learn(self, question, answers, now):
        addresses, ttl, target = address_chain(question, answers)
        if addresses or target is not None:
            self.records.publish(question, ttl, now, addresses=addresses, target=target)


def attach_dns_filter(connection):
    """Attach a classic BPF filter to a cooked Linux socket (IP header at byte 0)."""
    class Instruction(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("yes", ctypes.c_ubyte),
                    ("no", ctypes.c_ubyte), ("value", ctypes.c_uint)]

    class Program(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ushort), ("instructions", ctypes.POINTER(Instruction))]

    # 0-2 identify IPv4. 3-9 inspect its UDP header after the variable IP
    # header. 10-16 handle IPv6 with an immediate UDP header. 17/18 accept/drop.
    code = [
        (0x30, 0, 0, 0), (0x54, 0, 0, 0xF0), (0x15, 0, 7, 0x40),
        (0x30, 0, 0, 9), (0x15, 0, 13, 17), (0xB1, 0, 0, 0),
        (0x48, 0, 0, 0), (0x15, 9, 0, 53), (0x48, 0, 0, 2), (0x15, 7, 8, 53),
        (0x15, 0, 7, 0x60), (0x30, 0, 0, 6), (0x15, 0, 5, 17),
        (0x28, 0, 0, 40), (0x15, 2, 0, 53), (0x28, 0, 0, 42), (0x15, 0, 1, 53),
        (0x06, 0, 0, 65535), (0x06, 0, 0, 0),
    ]
    instructions = (Instruction * len(code))(*(Instruction(*row) for row in code))
    program = Program(len(code), instructions)
    # Linux SO_ATTACH_FILTER consumes the program and copies its instructions.
    connection.setsockopt(socket.SOL_SOCKET, 26, bytes(program))


def open_capture(interface):
    if not hasattr(socket, "AF_PACKET"):
        raise ValueError("WAN capture requires Linux")
    socket.if_nametoindex(interface)
    # Start with protocol 0 so the socket receives nothing until after bind.
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, 0)
    try:
        attach_dns_filter(connection)
        connection.bind((interface, 3))  # ETH_P_ALL, host byte order in Python
        connection.settimeout(0.5)
        return connection
    except BaseException:
        connection.close()
        raise


def watch_wan(connection, learner, stop):
    while not stop.is_set():
        try:
            packet, address = connection.recvfrom(65535)
        except TimeoutError:
            continue
        except OSError as error:
            if not stop.is_set():
                logging.error("WAN capture stopped: %s", error)
            return
        packet_type = address[2]
        if packet_type in (0, 4):  # PACKET_HOST or PACKET_OUTGOING
            learner.observe(packet, packet_type == 4, time.monotonic())


def validate_tld_download(name, contents):
    if name == "tlds-alpha-by-domain.txt":
        lines = contents.splitlines()
        if (not lines or not lines[0].startswith(b"# Version ")
                or not {b"COM", b"NET", b"ORG"}.issubset(lines[1:])
                or not all(re.fullmatch(rb"[A-Z0-9-]{1,63}", label) for label in lines[1:])):
            raise ValueError("invalid public TLD list")
    elif not (re.search(rb"(?m)^\.[ \t]+[0-9]+[ \t]+IN[ \t]+SOA[ \t]", contents)
              and re.search(rb"(?m)^com\.[ \t]+[0-9]+[ \t]+IN[ \t]+NS[ \t]", contents)):
        raise ValueError("invalid public root zone")


def fetch_snapshot(url, addresses, limit):
    parsed = urlsplit(url)
    port = parsed.port or 443
    errors = []
    for address in addresses:
        target = f"[{address}]" if ":" in address else address
        try:
            result = subprocess.run(
                ["curl", "--disable", "--noproxy", "*", "--proto", "=https", "--globoff",
                 "--fail", "--silent", "--show-error", "--connect-timeout", "3",
                 "--max-time", "10", "--max-filesize", str(limit),
                 "--resolve", f"{parsed.hostname}:{port}:{target}", "--url", url],
                capture_output=True, timeout=12, check=True,
            )
        except subprocess.CalledProcessError as error:
            errors.append(f"curl exited with status {error.returncode}")
            continue
        except subprocess.TimeoutExpired:
            errors.append("curl timed out")
            continue
        if len(result.stdout) > limit:
            raise ValueError("oversized download")
        return result.stdout
    raise ValueError(f"unable to fetch {parsed.hostname}: {'; '.join(errors)}")


def write_snapshot(path, contents):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as output:
            temporary = Path(output.name)
            output.write(contents)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def write_split_files(directory, entries):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    manifest = directory / ".tekzite-generated"
    try:
        previous = json.loads(manifest.read_bytes())
    except FileNotFoundError:
        previous = {}
    if not isinstance(previous, dict) or any(
        not re.fullmatch(r"[a-z0-9_.*-]+\.json", name) or not isinstance(digest, str)
        for name, digest in previous.items()
    ):
        raise ValueError(f"invalid generated-file manifest in {directory}")

    output = {name: (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
              for name, value in entries.items()}
    current = {name: hashlib.sha256(contents).hexdigest() for name, contents in output.items()}
    for name, contents in output.items():
        path = directory / name
        if path.exists():
            existing = path.read_bytes()
            if existing == contents:
                continue
            if hashlib.sha256(existing).hexdigest() != previous.get(name):
                raise ValueError(f"refusing to overwrite unmanaged file {path}")
        write_snapshot(path, contents)
    for name in previous.keys() - current.keys():
        path = directory / name
        if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() == previous[name]:
            path.unlink()
    if previous != current:
        write_snapshot(manifest, (json.dumps(current, sort_keys=True) + "\n").encode())


def tld_export_entries(contents):
    validate_tld_download("root.zone", contents)
    delegations, _ = read_registry_snapshot(contents.decode("ascii").splitlines())
    return {
        f"{name_text(zone).rstrip('.')}.json": {
            "tld": name_text(zone),
            "nameservers": {name_text(host): sorted(addresses) for host, addresses in hosts.items()},
        }
        for zone, hosts in delegations.items()
    }


def prepare_zone_exports(authority, contents):
    zones = authority.prepare_downloaded_zones(contents)
    config = json.loads(contents)
    entries = {f"{name_text(domain(item['origin'])).rstrip('.')}.zone.json": item
               for item in (config if isinstance(config, list) else [config])}
    return zones, entries


def install_zone_bundle(authority, directory, prepared):
    zones, entries = prepared
    write_split_files(directory, entries)
    authority.install_downloaded_zones(zones)


@dataclass(frozen=True)
class SnapshotSource:
    path: Path
    url: str
    addresses: tuple[str, ...]
    limit: int
    validate: Callable
    install: Callable | None = None
    refresh_seconds: int = TLD_REFRESH_SECONDS


def refresh_snapshots(sources, stop):
    pending_install = {source.path for source in sources if source.install is not None}
    while not stop.is_set():
        delay = TLD_REFRESH_SECONDS
        for source in sources:
            if stop.is_set():
                return
            path = source.path
            try:
                try:
                    age = time.time() - path.stat().st_mtime
                except FileNotFoundError:
                    age = source.refresh_seconds
                if 0 <= age < source.refresh_seconds:
                    if path in pending_install:
                        source.install(source.validate(path.read_bytes()))
                        pending_install.discard(path)
                    delay = min(delay, source.refresh_seconds - age)
                    continue
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                contents = fetch_snapshot(source.url, source.addresses, source.limit)
                validated = source.validate(contents)
                write_snapshot(path, contents)
                if source.install is not None:
                    pending_install.add(path)
                    source.install(validated)
                    pending_install.discard(path)
                logging.info("downloaded DNS snapshot %s (refresh every %ds)", path, source.refresh_seconds)
            except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
                delay = min(delay, TLD_RETRY_SECONDS)
                logging.warning("could not update DNS snapshot %s: %s", path, error)
        stop.wait(delay)




# RPZ QNAME policy engine. Uses dnspython's RFC 1035 zone-file parser to
# understand $ORIGIN, $TTL, multiline SOA, escaped labels and wildcard RRs.
# RPZ zones are independent of locally served authoritative zones.
class RPZEngine:
    def __init__(self, specs):
        self.specs = tuple(specs)
        self._zones = ()
        self._signatures = None
        self._lock = threading.Lock()
        self.reload(force=True)

    def reload(self, force=False):
        import dns.zone
        import dns.rdatatype
        signatures = tuple((str(path), path.stat().st_mtime_ns, path.stat().st_size)
                           for _, path in self.specs)
        if not force and signatures == self._signatures:
            return False
        prepared = []
        for origin_text, path in self.specs:
            origin = domain(origin_text)
            zone = dns.zone.from_file(str(path), origin=origin_text, relativize=False,
                                      check_origin=False, allow_include=False)
            policies = {}
            for owner, node in zone.nodes.items():
                owner_tuple = domain(owner.to_text())
                if not under(owner_tuple, origin) or owner_tuple == origin:
                    continue
                # RPZ IP, NSDNAME and NSIP triggers need a separate processing
                # pipeline; never mistake them for ordinary QNAME triggers.
                relative = owner_tuple[:-len(origin)]
                if relative and relative[-1] == b'rpz-ip':
                    continue
                if relative and relative[-1] in (b'rpz-nsdname', b'rpz-nsip', b'rpz-client-ip'):
                    continue
                rrset = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.CNAME)
                if rrset:
                    if len(rrset) != 1:
                        raise ValueError(f'RPZ conflicting CNAMEs at {owner}')
                    target = domain(next(iter(rrset)).target.to_text())
                    if target == ROOT:
                        action = ('NXDOMAIN', None)
                    elif target == (b'*',):
                        action = ('NODATA', None)
                    elif target == (b'rpz-passthru',):
                        action = ('PASSTHRU', None)
                    elif target == (b'rpz-drop',):
                        action = ('DROP', None)
                    elif target == (b'rpz-tcp-only',):
                        action = ('TCP-ONLY', None)
                    else:
                        action = ('CNAME', target)
                else:
                    a = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.A)
                    aaaa = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.AAAA)
                    if not a and not aaaa:
                        continue
                    records = []
                    for rrset, kind in ((a, A), (aaaa, AAAA)):
                        if rrset:
                            for item in rrset:
                                records.append((kind, ipaddress.ip_address(item.address).packed,
                                                min(rrset.ttl, MAX_TTL)))
                    action = ('ADDRESS', tuple(records))
                policies[relative] = action
            prepared.append((origin_text, policies))
        with self._lock:
            self._zones = tuple(prepared)
            self._signatures = signatures
        logging.info('RPZ loaded: %s', ', '.join('%s (%d rules)' % (name, len(rules))
                                                    for name, rules in prepared))
        return True

    def match(self, name):
        with self._lock:
            zones = self._zones
        for origin, rules in zones:
            # Exact is more specific than wildcard; a wildcard policy matches
            # any descendant but not the wildcard's parent itself.
            matched = rules.get(name)
            if matched is None:
                for start in range(1, len(name)):
                    matched = rules.get((b'*',) + name[start:])
                    if matched is not None:
                        break
            if matched is not None:
                return origin, matched
        return None

    def apply(self, question, reply=None, *, tcp=False):
        if question.cls != IN:
            return reply
        names = [question.name]
        if reply is not None:
            # Also inspect all CNAME targets, including cached CNAME chains.
            for rr in reply.answers:
                if rr.kind == CNAME:
                    try:
                        names.append(rr.target())
                    except WireError:
                        pass
        for name in names:
            found = self.match(name)
            if not found:
                continue
            origin, (action, value) = found
            logging.info('RPZ %s zone=%s qname=%s trigger=%s',
                         action, origin, name_text(question.name), name_text(name))
            if action == 'PASSTHRU':
                return reply
            if action == 'NXDOMAIN':
                return Reply(NXDOMAIN)
            if action == 'NODATA':
                return Reply(OK)
            if action == 'DROP':
                return 'DROP'
            if action == 'TCP-ONLY':
                return reply if tcp else 'TCP-ONLY'
            if action == 'CNAME':
                return Reply(OK, (Record(question.name, CNAME, IN, 60, name_wire(value)),))
            if action == 'ADDRESS':
                answers = tuple(Record(question.name, kind, IN, ttl, data)
                                for kind, data, ttl in value if question.kind in (kind, ANY))
                return Reply(OK, answers)
        return reply


def watch_rpz(engine, stop, interval=30):
    while not stop.wait(interval):
        try:
            engine.reload()
        except (OSError, ValueError, ImportError) as error:
            logging.error('RPZ reload failed; preserving last valid policy: %s', error)

def prune_expired_ondemand(connection, now, batch_size=500):
    """Delete a bounded number of expired rows per table in one transaction.

    Intended for opportunistic maintenance on successful cache writes. Expired
    entries are never returned even when a backlog remains.
    """
    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    counts = []
    for table in ("ondemand", "ondemand_negative"):
        cursor = connection.execute(
            f"DELETE FROM {table} WHERE rowid IN ("
            f"SELECT rowid FROM {table} WHERE expires <= ? LIMIT ?)",
            (now, batch_size),
        )
        counts.append(cursor.rowcount)
    return tuple(counts)


class Authority:
    def __init__(self, zones, learned, resolve_wan=False, resolver=None, fdns_db=None, ondemand_db=None, rpz=None, lan_domains=()):
        if isinstance(zones, Zone):
            zones = (zones,)
        self.local_zones = tuple(sorted(zones, key=lambda zone: len(zone.origin), reverse=True))
        self.zones = {zone.origin: zone for zone in self.local_zones}
        if not self.local_zones:
            raise ValueError("at least one authoritative zone is required")
        if len(self.zones) != len(self.local_zones):
            raise ValueError("duplicate zone origin")
        self.learned = learned
        self.rpz = rpz
        self.lan_domains = tuple(x.lower().rstrip(".") for x in lan_domains)
        self.resolve_wan = resolve_wan
        self.fdns_db = fdns_db
        self.ondemand_db = ondemand_db
        self.ondemand_lock = threading.Lock()
        self.ondemand_last_prune = 0.0
        self.ondemand_local = threading.local()
        self.ondemand_key_locks = tuple(
            threading.Lock() for _ in range(128)
        )
        if ondemand_db is not None:
            with closing(sqlite3.connect(ondemand_db)) as db, db:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute(
                    "CREATE TABLE IF NOT EXISTS ondemand "
                    "(name TEXT, type TEXT, value TEXT, "
                    "expires REAL, PRIMARY KEY(name,type,value))"
                )
                db.execute(
                    "CREATE TABLE IF NOT EXISTS ondemand_negative "
                    "(name TEXT, type TEXT, rcode INTEGER, expires REAL, "
                    "PRIMARY KEY(name,type))"
                )
                db.execute("CREATE INDEX IF NOT EXISTS ondemand_expires_idx ON ondemand(expires)")
                db.execute("CREATE INDEX IF NOT EXISTS ondemand_negative_expires_idx ON ondemand_negative(expires)")
        self.resolver = resolver if resolver is not None else ResolverState()

    def maybe_prune_ondemand(self, connection):
        # Serialized, time-limited cleanup. Use a small batch to avoid a long
        # writer transaction on a busy LAN resolver.
        with self.ondemand_lock:
            now = time.monotonic()
            if now - self.ondemand_last_prune < 300:
                return
            prune_expired_ondemand(connection, time.time())
            self.ondemand_last_prune = now

    def prepare_downloaded_zones(self, contents):
        downloaded = zones_from_config(json.loads(contents))
        if not downloaded or any(not zone.origin for zone in downloaded):
            raise ValueError("download must contain at least one non-root zone")
        if len({zone.origin for zone in downloaded}) != len(downloaded):
            raise ValueError("duplicate downloaded zone origin")
        if any(under(zone.origin, local.origin) or under(local.origin, zone.origin)
               for zone in downloaded for local in self.local_zones):
            raise ValueError("downloaded zone overlaps a locally configured zone")
        return sorted((*self.local_zones, *downloaded), key=lambda zone: len(zone.origin), reverse=True)

    def install_downloaded_zones(self, zones):
        self.zones = {zone.origin: zone for zone in zones}

    def answer_from_fdns(self, question):
        if self.fdns_db is None:
            return None
        if question.kind not in (A, AAAA, CNAME):
            return None
        if question.cls != IN or not wan_name(question.name):
            return None

        hostname = name_text(lower_name(question.name)).rstrip(".")
        kind = {A: "A", AAAA: "AAAA", CNAME: "CNAME"}[question.kind]

        try:
            uri = self.fdns_db.resolve().as_uri() + "?mode=ro"
            connection = sqlite3.connect(uri, uri=True, timeout=2)
            try:
                rows = connection.execute(
                    "SELECT type, value FROM records "
                    "WHERE name=? AND type IN (?, 'CNAME') LIMIT 65",
                    (hostname, kind)
                ).fetchall()
            finally:
                connection.close()
        except sqlite3.Error as error:
            logging.warning("FDNS database lookup failed: %s", error)
            return Reply(SERVFAIL)

        answers = []
        aliases = []

        for record_type, value in rows:
            try:
                if record_type == "A" and kind == "A":
                    data = ipaddress.IPv4Address(value).packed
                    answers.append(Record(question.name, A, IN, 300, data))
                elif record_type == "AAAA" and kind == "AAAA":
                    data = ipaddress.IPv6Address(value).packed
                    answers.append(Record(question.name, AAAA, IN, 300, data))
                elif record_type == "CNAME":
                    data = name_wire(domain(value + "."))
                    aliases.append(Record(question.name, CNAME, IN, 300, data))
            except (ValueError, TypeError, UnicodeError):
                continue

        if answers:
            logging.debug("FDNS hit %s type=%s", hostname, kind)
            return Reply(OK, tuple(answers))

        if aliases:
            logging.debug("FDNS CNAME hit %s", hostname)
            return Reply(OK, tuple(aliases[:1]))

        return None



    def ondemand_connection(self):
        connection = getattr(
            self.ondemand_local, "connection", None
        )
        if connection is None:
            connection = sqlite3.connect(
                self.ondemand_db, timeout=5
            )
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA busy_timeout=5000")
            self.ondemand_local.connection = connection
        return connection


    def answer_on_demand(self, question):
        if self.ondemand_db is None or question.cls != IN:
            return None
        if question.kind not in (A, AAAA, CNAME):
            return None
        if not wan_name(question.name):
            return None

        from contextlib import closing
        import dns.resolver
        import dns.exception

        hostname = name_text(lower_name(question.name)).rstrip(".")
        kind = {A: "A", AAAA: "AAAA", CNAME: "CNAME"}[question.kind]
        # LAN overrides should follow current local Unbound configuration,
        # not an older public answer retained in SQLite.
        refresh_lan = any(
            hostname == suffix or hostname.endswith("." + suffix)
            for suffix in self.lan_domains
        )

        def cached_reply():
            now = time.time()
            current = hostname
            chain = []
            visited = set()

            for _ in range(9):
                if current in visited:
                    return None
                visited.add(current)

                rows = connection.execute(
                    "SELECT type,value,expires FROM ondemand "
                    "WHERE name=? AND expires>? "
                    "AND type IN ('A','AAAA','CNAME')",
                    (current, now)
                ).fetchall()

                aliases = [
                    (value, expires)
                    for typ, value, expires in rows
                    if typ == "CNAME"
                ]

                if aliases:
                    # CNAME always wins over A/AAAA at its owner.
                    target, expiry = sorted(aliases)[0]
                    try:
                        target_name = domain(target.rstrip(".") + ".")
                    except (ValueError, UnicodeError):
                        return None

                    owner = domain(current + ".")
                    chain.append(Record(
                        owner, CNAME, IN,
                        max(1, int(expiry - now)),
                        name_wire(target_name)
                    ))

                    if kind == "CNAME":
                        return Reply(OK, tuple(chain))

                    current = target.rstrip(".").lower()
                    continue

                if kind == "CNAME":
                    return Reply(OK, tuple(chain)) if chain else None

                addresses = []
                for typ, value, expiry in rows:
                    if typ != kind:
                        continue
                    try:
                        address = ipaddress.ip_address(value)
                        if address.version != (4 if kind == "A" else 6):
                            continue
                        addresses.append(Record(
                            domain(current + "."),
                            question.kind, IN,
                            max(1, int(expiry - now)),
                            address.packed
                        ))
                    except (ValueError, UnicodeError):
                        continue

                if addresses:
                    logging.debug(
                        "SQLite cache hit: %s %s",
                        hostname, kind
                    )
                    return Reply(OK, tuple(chain + addresses))

                return None

            return None

        try:
            connection = self.ondemand_connection()
            result = None if refresh_lan else cached_reply()
            if result is not None:
                return result
            negative = None if refresh_lan else connection.execute(
                "SELECT rcode FROM ondemand_negative "
                "WHERE name=? AND type IN (?, '*') AND expires>? "
                "ORDER BY CASE WHEN type='*' THEN 0 ELSE 1 END LIMIT 1",
                (hostname, kind, time.time())
            ).fetchone()
            if negative is not None:
                return Reply(int(negative[0]))

            lock = self.ondemand_key_locks[
                hash((hostname, kind)) % len(self.ondemand_key_locks)
            ]

            with lock:
                result = None if refresh_lan else cached_reply()
                if result is not None:
                    return result
                negative = None if refresh_lan else connection.execute(
                    "SELECT rcode FROM ondemand_negative "
                    "WHERE name=? AND type IN (?, '*') AND expires>? "
                    "ORDER BY CASE WHEN type='*' THEN 0 ELSE 1 END LIMIT 1",
                    (hostname, kind, time.time())
                ).fetchone()
                if negative is not None:
                    return Reply(int(negative[0]))

                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = ["127.0.0.1"]
                resolver.port = 53
                resolver.timeout = 2
                resolver.lifetime = 4

                def store_negative(response, rcode):
                    # RFC 2308: only cache negative answers with an SOA and
                    # cap lifetime at min(SOA TTL, SOA.MINIMUM, 300s).
                    import dns.rdatatype
                    from contextlib import closing
                    if response is not None:
                        for rrset in response.authority:
                            if rrset.rdtype == dns.rdatatype.SOA and len(rrset):
                                ttl = min(int(rrset.ttl), int(rrset[0].minimum), 300)
                                if ttl > 0:
                                    with closing(sqlite3.connect(self.ondemand_db, timeout=10)) as db, db:
                                        db.execute(
                                            "INSERT OR REPLACE INTO ondemand_negative "
                                            "(name,type,rcode,expires) VALUES (?,?,?,?)",
                                            (hostname, '*' if rcode == NXDOMAIN else kind,
                                             rcode, time.time() + ttl)
                                        )
                                        self.maybe_prune_ondemand(db)
                                break
                    return Reply(rcode)

                try:
                    answer = resolver.resolve(
                        hostname, kind, search=False
                    )
                except dns.resolver.NXDOMAIN as error:
                    responses = error.responses()
                    response = next(iter(responses.values()), None)
                    return store_negative(response, NXDOMAIN)
                except dns.resolver.NoAnswer as error:
                    return store_negative(error.response(), OK)

                groups = {}
                now = time.time()

                # Preserve original owner names and TTLs.
                for rrset in answer.response.answer:
                    record_type = dns.rdatatype.to_text(rrset.rdtype)
                    if record_type not in ("A", "AAAA", "CNAME"):
                        continue

                    owner = rrset.name.to_text().lower().rstrip(".")
                    ttl = max(1, min(int(rrset.ttl), 300))
                    values = []

                    for record in rrset:
                        try:
                            if record_type in ("A", "AAAA"):
                                address = ipaddress.ip_address(
                                    record.address
                                )
                                # Only explicitly trusted LAN DNS names may resolve
                                # to non-public IPs. This prevents DNS rebinding.
                                lan_allowed = any(
                                    owner == suffix or owner.endswith("." + suffix)
                                    for suffix in self.lan_domains
                                )
                                if not address.is_global:
                                    if not lan_allowed or not (
                                        address in ipaddress.ip_network("10.0.0.0/8")
                                        or address in ipaddress.ip_network("172.16.0.0/12")
                                        or address in ipaddress.ip_network("192.168.0.0/16")
                                        or address in ipaddress.ip_network("fc00::/7")
                                    ):
                                        continue
                                values.append(str(address))
                            else:
                                target = record.target.to_text()
                                target = target.lower().rstrip(".")
                                domain(target + ".")
                                values.append(target)
                        except (ValueError, UnicodeError):
                            continue

                    if values:
                        groups[(owner, record_type)] = (
                            values, now + ttl
                        )

                if not groups:
                    return Reply(SERVFAIL)

                # Write complete RRsets in one transaction.
                with closing(sqlite3.connect(self.ondemand_db, timeout=10)) as db, db:
                    db.execute("BEGIN IMMEDIATE")
                    db.execute(
                        "DELETE FROM ondemand_negative WHERE name=? AND type IN (?, '*')",
                        (hostname, kind)
                    )

                    for (owner, typ), (values, expiry) in groups.items():
                        db.execute(
                            "DELETE FROM ondemand "
                            "WHERE name=? AND type=?",
                            (owner, typ)
                        )
                        db.executemany(
                            "INSERT OR REPLACE INTO ondemand "
                            "(name,type,value,expires) "
                            "VALUES (?,?,?,?)",
                            [
                                (owner, typ, value, expiry)
                                for value in values
                            ]
                        )

                    self.maybe_prune_ondemand(db)

                    # Remove incorrectly synthesized alias addresses.
                    for owner, typ in groups:
                        if typ == "CNAME":
                            db.execute(
                                "DELETE FROM ondemand "
                                "WHERE name=? AND type IN ('A','AAAA')",
                                (owner,)
                            )
                        elif typ in ("A", "AAAA") and (owner, "CNAME") not in groups:
                            db.execute(
                                "DELETE FROM ondemand WHERE name=? AND type='CNAME'",
                                (owner,)
                            )

                result = cached_reply()
                if result is not None:
                    logging.info(
                        "Learned DNS chain: %s %s",
                        hostname, kind
                    )
                    return result

                return Reply(SERVFAIL)

        except (
            dns.exception.DNSException,
            OSError,
            sqlite3.Error,
            ValueError,
            UnicodeError
        ) as error:
            logging.warning(
                "DNS lookup failed %s %s: %s",
                hostname, kind, error
            )
            return Reply(SERVFAIL)
        finally:
            reader = getattr(self.ondemand_local, "connection", None)
            if reader is not None:
                del self.ondemand_local.connection
                reader.close()

    def answer(self, question, recurse=False):
        zones = self.zones
        matching = []
        for start in range(len(question.name) + 1):
            zone = zones.get(question.name[start:])
            if zone is not None:
                matching.append(zone)
        if matching:
            zone = matching[0]
            if question.kind == DS and question.name == zone.origin and len(matching) > 1:
                parent = matching[1]
                if parent.cut(question.name) == question.name:
                    return parent.answer(question)
            return zone.answer(question)
        # Explicit LAN domains take precedence over learned/FDNS public data.
        if self.ondemand_db is not None and any(
            name_text(lower_name(question.name)).rstrip(".") == suffix
            or name_text(lower_name(question.name)).rstrip(".").endswith("." + suffix)
            for suffix in self.lan_domains
        ):
            result = self.answer_on_demand(question)
            if result is not None:
                return result
        records = self.learned.answer(question, time.monotonic())
        if records:
            logging.debug("learned cache hit %s type=%d", name_text(question.name), question.kind)
            return Reply(OK, records)
        fdns_reply = self.answer_from_fdns(question)
        if fdns_reply is not None:
            return fdns_reply
        result = self.answer_on_demand(question)
        if result is not None:
            return result
        if (not self.resolve_wan or not recurse or question.kind not in (A, AAAA)
                or not wan_name(question.name)):
            return Reply(REFUSED)
        try:
            reply = IterativeLookup(8, self.resolver).resolve(question)
        except ResolutionError as error:
            logging.debug("DNS command failed: %s", error)
            return Reply(SERVFAIL)

        if reply.code != OK:
            return reply
        addresses, ttl, _ = address_chain(question, reply.answers)
        if not addresses:
            return reply
        self.learned.publish(question, ttl, time.monotonic(), addresses=addresses)
        return Reply(OK, tuple(Record(question.name, question.kind, IN, ttl, data)
                               for data in addresses))

    def handle(self, packet, tcp=False):
        if len(packet) < 12:
            return None
        txid, flags, qd, an, ns, ar = struct.unpack_from("!6H", packet)
        if flags & QR:
            return None
        question = None
        opt = None
        force_truncation = False
        if flags & 0x7800:
            reply = Reply(NOTIMP)
        elif flags & 0x0040:
            # The DNS header Z bit is reserved. AD/CD are not this bit.
            reply = Reply(FORMERR)
        elif qd != 1 or an or ns:
            reply = Reply(FORMERR)
        else:
            try:
                question, offset = read_question(packet)
                _, _, extra = read_sections(packet, offset, (0, 0, ar))
                if extra:
                    if len(extra) != 1 or extra[0].kind != OPT or extra[0].name:
                        raise WireError("unsupported additional record")
                    opt = extra[0]
                    validate_edns_options(opt.data)
                    # Only the DNSSEC OK (DO) flag is defined in EDNS(0).
                    # Reject unknown EDNS flag bits rather than interpreting them.
                    if opt.ttl & 0x7fff:
                        raise WireError("reserved EDNS flags set")
                if opt and ((opt.ttl >> 16) & 255):
                    reply = Reply(BADVERS)
                elif question.cls != IN or question.kind in (0, OPT, 249, 250, 251, 252, 253, 254):
                    reply = Reply(NOTIMP)
                else:
                    canonical = question.canonical()
                    policy = self.rpz.apply(canonical, tcp=tcp) if self.rpz else None
                    if policy is None:
                        reply = self.answer(canonical, bool(flags & RD))
                        if self.rpz:
                            policy = self.rpz.apply(canonical, reply, tcp=tcp)
                    if policy == 'DROP':
                        return None
                    if policy == 'TCP-ONLY':
                        if tcp:
                            reply = self.answer(canonical, bool(flags & RD))
                        else:
                            # Return truncated response to force TCP retry.
                            reply = Reply(OK)
                            force_truncation = True
                    elif policy is not None:
                        reply = policy
            except WireError:
                reply = Reply(FORMERR)

        limit = 65535 if tcp else max(512, min(UDP_SIZE, opt.cls)) if opt else 512
        question_wire = question.wire() if question else b""
        opt_wire = Record(ROOT, OPT, UDP_SIZE, (reply.code >> 4) << 24, b"").wire() if opt else b""
        # Emit whole sections or a minimal truncated response so TCP can retry.
        answer_wire = b"".join(rr.wire() for rr in reply.answers)
        authority_wire = b"".join(rr.wire() for rr in reply.authority)
        additional_wire = b"".join(rr.wire() for rr in reply.additional)
        response_flags = QR | (flags & (RD | 0x7800)) | (reply.code & 15)
        if reply.authoritative:
            response_flags |= AA
        if self.resolve_wan or self.ondemand_db is not None:
            response_flags |= RA
        counts = (len(reply.answers), len(reply.authority), len(reply.additional))
        size = 12 + len(question_wire) + len(answer_wire) + len(authority_wire) + len(additional_wire) + len(opt_wire)
        if size > limit or force_truncation:
            if tcp:
                response_flags = (response_flags & ~15) | SERVFAIL
            else:
                response_flags |= TC
            answer_wire = authority_wire = additional_wire = b""
            counts = (0, 0, 0)
        return (struct.pack("!6H", txid, response_flags, int(question is not None),
                            *counts[:2], counts[2] + int(opt is not None))
                + question_wire + answer_wire + authority_wire + additional_wire + opt_wire)


def client_allowed(address, networks):
    """Return whether a DNS peer is permitted by the configured CIDR allowlist."""
    try:
        ip = ipaddress.ip_address(address)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        return any(ip in network for network in networks)
    except ValueError:
        return False


class ClientRateLimiter:
    """Bounded, thread-safe token bucket keyed by client IP.

    At capacity, a new peer is rejected rather than evicting a current peer's
    state, which would let rotating source addresses reset their token buckets.
    """

    def __init__(self, rate, burst, max_clients=4096, idle_seconds=120):
        if rate <= 0 or burst <= 0 or max_clients <= 0 or idle_seconds <= 0:
            raise ValueError("rate, burst, max_clients and idle_seconds must be positive")
        self.rate = rate
        self.burst = burst
        self.max_clients = max_clients
        self.idle_seconds = idle_seconds
        self.lock = threading.Lock()
        self.buckets = {}

    def allow(self, address, now=None):
        try:
            ip = ipaddress.ip_address(address)
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            key = str(ip)
        except ValueError:
            return False
        if now is None:
            now = time.monotonic()
        with self.lock:
            previous = self.buckets.get(key)
            if previous is None:
                if len(self.buckets) >= self.max_clients:
                    expired = [peer for peer, (_, last) in self.buckets.items()
                               if now - last > self.idle_seconds]
                    for peer in expired:
                        del self.buckets[peer]
                if len(self.buckets) >= self.max_clients:
                    return False
                tokens = float(self.burst)
            else:
                tokens = min(self.burst, previous[0] + max(0, now - previous[1]) * self.rate)
            allowed = tokens >= 1
            self.buckets[key] = (tokens - 1 if allowed else tokens, now)
            return allowed


class LimitedThreads(socketserver.ThreadingMixIn):
    daemon_threads = True

    def __init__(self, address, handler, resolver, family=socket.AF_INET, *, ipv6_only=False, allowed_clients=(), max_workers=32, rate_limiter=None):
        self.address_family = family
        self.ipv6_only = ipv6_only
        self.resolver = resolver
        self.allowed_clients = tuple(allowed_clients)
        if max_workers < 1:
            raise ValueError("max_workers must be positive")
        self.slots = threading.BoundedSemaphore(max_workers)
        self.rate_limiter = rate_limiter
        super().__init__(address, handler)

    def server_bind(self):
        if self.address_family == socket.AF_INET6 and self.ipv6_only:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()

    def process_request(self, request, client_address):
        if not client_allowed(client_address[0], self.allowed_clients):
            self.shutdown_request(request)
            return
        if self.rate_limiter is not None and not self.rate_limiter.allow(client_address[0]):
            self.shutdown_request(request)
            return
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class UdpServer(LimitedThreads, socketserver.UDPServer):
    max_packet_size = 65535


class TcpServer(LimitedThreads, socketserver.TCPServer):
    allow_reuse_address = True
    request_queue_size = 64


class DotServer(TcpServer):
    """DNS-over-TLS listener, sharing the normal resolver and client limits."""

    def __init__(self, address, handler, resolver, family=socket.AF_INET, *, ssl_context, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(address, handler, resolver, family, **kwargs)


class UdpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        if not client_allowed(self.client_address[0], self.server.allowed_clients):
            return
        packet, connection = self.request
        reply = self.server.resolver.handle(packet)
        if reply is not None:
            connection.sendto(reply, self.client_address)


class TcpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        if not client_allowed(self.client_address[0], self.server.allowed_clients):
            return
        connection = self.request
        try:
            session_deadline = time.monotonic() + 30
            for _ in range(32):
                deadline = min(time.monotonic() + 5, session_deadline)
                size, = struct.unpack("!H", receive_exact(connection, 2, deadline))
                packet = receive_exact(connection, size, deadline)
                reply = self.server.resolver.handle(packet, tcp=True)
                if reply is None:
                    return
                connection.settimeout(min(5, time_left(session_deadline)))
                connection.sendall(struct.pack("!H", len(reply)) + reply)
        except (OSError, EOFError):
            return


class DotHandler(TcpHandler):
    """Authenticate TLS transport before processing length-prefixed DNS frames."""

    def handle(self):
        # Authorization and rate limits are enforced by LimitedThreads before
        # this handler runs. Do not respond to plaintext requests on this port.
        try:
            self.request.settimeout(5)
            with self.server.ssl_context.wrap_socket(self.request, server_side=True) as secure:
                secure.settimeout(5)
                self.request = secure
                super().handle()
        except (OSError, EOFError, ssl.SSLError):
            # Invalid TLS handshakes should not produce tracebacks or DNS replies.
            return


def build_dot_context(certfile, keyfile):
    """Create the server context at startup; a service restart loads renewed keys."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    return context


def zones_from_config(config):
    return [Zone(item) for item in (config if isinstance(config, list) else [config])]


def main():
    parser = argparse.ArgumentParser(description="Authoritative DNS with optional active and passive WAN learning")
    parser.add_argument("--zone", type=Path, action="append", metavar="JSON",
                        help="load one zone or a list of zones from a JSON file (repeatable)")
    parser.add_argument("--zone-dir", type=Path, action="append", metavar="DIRECTORY",
                        help="load all JSON zone files in a directory (repeatable)")
    examples = parser.add_mutually_exclusive_group()
    examples.add_argument("--example-zone", action="store_true", help="print the editable demo zone and exit")
    examples.add_argument("--example-private-zones", action="store_true",
                          help="print the editable .internal TLD and child zone and exit")
    parser.add_argument("--listen", type=ipaddress.ip_address, action="append", metavar="IP",
                        help="listen on this IPv4 or IPv6 address (repeatable, default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5533)
    parser.add_argument("--dot-listen", type=ipaddress.ip_address, action="append", metavar="IP",
                        help="optional DoT listener IP; repeatable; must be loopback or private LAN")
    parser.add_argument("--dot-port", type=int, default=853, metavar="PORT",
                        help="DNS-over-TLS TCP port (default 853; use 8853 for staging)")
    parser.add_argument("--dot-cert", type=Path, metavar="PEM",
                        help="fullchain PEM for DoT (required with --dot-listen)")
    parser.add_argument("--dot-key", type=Path, metavar="PEM",
                        help="private key PEM for DoT (required with --dot-listen)")
    parser.add_argument("--allow-client", type=ipaddress.ip_network, action="append", metavar="CIDR",
                        help="allowed client IPv4/IPv6 range (repeatable); default loopback only")
    parser.add_argument("--max-workers", type=int, default=32, metavar="N",
                        help="maximum concurrent request workers per listener (default 32)")
    parser.add_argument("--rate-limit", type=float, default=0.0, metavar="QPS",
                        help="per-client DNS queries per second (0 disables; default 0)")
    parser.add_argument("--rate-burst", type=int, default=200, metavar="N",
                        help="per-client burst tokens when rate limiting is enabled (default 200)")
    parser.add_argument("--learn-wan", metavar="INTERFACE", help="learn local A/AAAA overrides from WAN DNS")
    parser.add_argument("--resolve-wan", action="store_true", help="resolve public A/AAAA directly with dig")
    parser.add_argument("--ondemand-db", type=Path,
                        help="persistent on-demand DNS SQLite cache")
    parser.add_argument("--lan-domain", action="append", default=[], metavar="DOMAIN",
                        help="trust local Unbound overrides for this domain/subdomains (repeatable)")
    parser.add_argument("--fdns-db", type=Path,
                        help="read-only SQLite FDNS record database")
    parser.add_argument("--rpz", action="append", metavar="ZONE=FILE",
                        help="RPZ master zone, repeat in policy priority order; requires dnspython")
    parser.add_argument("--local-only", action="store_true", help="serve local zones without issuing any DNS lookups")
    parser.add_argument("--root-snapshot", type=Path,
                        help="local root-zone snapshot for TLD hints (default: tld-data/root.zone)")
    parser.add_argument("--auto-download-tlds", action="store_true",
                        help="refresh the public TLD list and root snapshot in tld-data/ every 24 hours")
    parser.add_argument("--zone-source", help="trusted HTTPS URL of a JSON zone file or list of zones")
    parser.add_argument("--zone-source-ip", type=ipaddress.ip_address, action="append", metavar="IP",
                        help="numeric HTTPS endpoint for --zone-source; repeat for failover")
    parser.add_argument("--no-root", action="store_true", help="compatibility flag; live DNS root queries are always blocked")
    parser.add_argument("--trace", action="store_true", help="log learning, cache hits and DNS commands")
    args = parser.parse_args()
    if args.example_zone:
        print(json.dumps(EXAMPLE_ZONE, indent=2))
        return
    if args.example_private_zones:
        print(json.dumps(PRIVATE_EXAMPLE_ZONES, indent=2))
        return
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if not 1 <= args.dot_port <= 65535:
        parser.error("--dot-port must be between 1 and 65535")
    if bool(args.dot_listen) != bool(args.dot_cert) or bool(args.dot_listen) != bool(args.dot_key):
        parser.error("--dot-listen, --dot-cert, and --dot-key must all be specified together")
    if args.dot_listen and args.dot_port == args.port and set(args.dot_listen) & set(args.listen or [ipaddress.ip_address("127.0.0.1")]):
        parser.error("DoT and plaintext TCP cannot share an address and port")
    if args.dot_listen and any(ip.is_unspecified or ip.is_global or ip.is_multicast for ip in args.dot_listen):
        parser.error("DoT listeners must use specific loopback or private LAN addresses")
    if not 1 <= args.max_workers <= 1024:
        parser.error("--max-workers must be between 1 and 1024")
    if not 0 <= args.rate_limit <= 100000 or not math.isfinite(args.rate_limit):
        parser.error("--rate-limit must be finite and between 0 and 100000")
    if not 1 <= args.rate_burst <= 100000:
        parser.error("--rate-burst must be between 1 and 100000")
    if args.no_root and not args.resolve_wan:
        parser.error("--no-root requires --resolve-wan")
    if args.local_only and args.ondemand_db:
        parser.error("--local-only cannot be used with --ondemand-db")
    if args.local_only and (args.resolve_wan or args.learn_wan):
        parser.error("--local-only cannot be combined with --resolve-wan or --learn-wan")
    if bool(args.zone_source) != bool(args.zone_source_ip):
        parser.error("--zone-source and --zone-source-ip must be provided together")
    if args.zone_source:
        try:
            source_url = urlsplit(args.zone_source)
            source_port = source_url.port
            source_host = source_url.hostname or ""
            if (source_url.scheme != "https"
                    or not re.fullmatch(r"(?:[a-z0-9][a-z0-9-]*\.)+[a-z][a-z0-9-]*", source_host)
                    or source_url.username is not None
                    or source_url.fragment or source_port == 0):
                raise ValueError
        except ValueError:
            parser.error("--zone-source must be an HTTPS URL with an ASCII hostname and no credentials or fragment")
    listen_ips = list(dict.fromkeys(args.listen or [ipaddress.ip_address("127.0.0.1")]))
    allowed_clients = tuple(args.allow_client or (
        ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")
    ))
    if any(not ip.is_loopback for ip in listen_ips + list(args.dot_listen or ())) and not args.allow_client:
        parser.error("non-loopback listeners require an explicit --allow-client CIDR")
    if (args.learn_wan or args.resolve_wan or args.ondemand_db) and any(
        ip.is_unspecified or ip.is_global for ip in listen_ips
    ):
        parser.error("WAN learning and on-demand recursion require specific loopback or private LAN listeners")
    if args.resolve_wan and shutil.which("dig") is None:
        parser.error("--resolve-wan requires dig on PATH")
    if (args.auto_download_tlds or args.zone_source) and shutil.which("curl") is None:
        parser.error("automatic snapshot downloads require curl on PATH")
    logging.basicConfig(level=logging.DEBUG if args.trace else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    config_dir = Path.cwd()
    if args.zone:
        config_dir = args.zone[0].parent
    elif args.zone_dir:
        config_dir = args.zone_dir[0]
    data_dir = config_dir / "tld-data"
    resolver = ResolverState(args.root_snapshot or data_dir / "root.zone")
    try:
        paths = list(args.zone or ())
        for directory in args.zone_dir or ():
            if not directory.is_dir():
                raise ValueError(f"zone directory does not exist: {directory}")
            paths.extend(sorted(path for path in directory.glob("*.json") if path.is_file()))
        if paths:
            zones = []
            for path in dict.fromkeys(paths):
                try:
                    zones.extend(zones_from_config(json.loads(path.read_text(encoding="utf-8"))))
                except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
                    raise ValueError(f"{path}: {error}") from error
        elif args.zone_dir:
            raise ValueError("no JSON zone files found in the configured directories")
        else:
            zones = zones_from_config(EXAMPLE_ZONE)
        learned = LearnedRecords()
        rpz_specs = []
        for spec in args.rpz or ():
            if '=' not in spec:
                raise ValueError('--rpz expects zone.name.=path/to/zonefile')
            rpz_name, rpz_path = spec.split('=', 1)
            domain(rpz_name)
            rpz_specs.append((rpz_name, Path(rpz_path)))
        rpz = RPZEngine(rpz_specs) if rpz_specs else None
        for suffix in args.lan_domain:
            if not suffix or suffix.startswith(".") or not wan_name(domain(suffix.rstrip(".") + ".")):
                raise ValueError("--lan-domain requires a valid external DNS domain")
        authority = Authority(zones, learned, args.resolve_wan, resolver, args.fdns_db,
                              args.ondemand_db, rpz, args.lan_domain)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        parser.error(f"invalid zone: {error}")
    sources = []
    export_dir = args.zone_dir[0] if args.zone_dir else None
    if args.auto_download_tlds:
        for name, (url, addresses, limit) in TLD_DOWNLOADS.items():
            if name == "root.zone" and export_dir is not None:
                sources.append(SnapshotSource(data_dir / name, url, addresses, limit, tld_export_entries,
                                              partial(write_split_files, export_dir / "delegations")))
            else:
                sources.append(SnapshotSource(data_dir / name, url, addresses, limit,
                                              partial(validate_tld_download, name)))
    if args.zone_source:
        source_id = hashlib.sha256(args.zone_source.encode()).hexdigest()[:16]
        cached_zones = data_dir / f"zones-{source_id}.json"
        validate = authority.prepare_downloaded_zones
        install = authority.install_downloaded_zones
        if export_dir is not None:
            validate = partial(prepare_zone_exports, authority)
            install = partial(install_zone_bundle, authority,
                              export_dir / "downloaded" / source_id)
        sources.append(SnapshotSource(cached_zones, args.zone_source, tuple(map(str, args.zone_source_ip)),
                                      8 * 1024 * 1024, validate, install,
                                      refresh_seconds=ZONE_REFRESH_SECONDS))
        try:
            authority.install_downloaded_zones(authority.prepare_downloaded_zones(cached_zones.read_bytes()))
        except FileNotFoundError:
            pass
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            logging.warning("could not load cached zones %s: %s", cached_zones, error)
    zone_names = ", ".join(name_text(origin) for origin in authority.zones)
    dot_ips = list(dict.fromkeys(args.dot_listen or ()))
    try:
        dot_context = build_dot_context(args.dot_cert, args.dot_key) if dot_ips else None
    except (OSError, ssl.SSLError, ValueError) as error:
        parser.error(f"could not load DoT certificate/key: {error}")
    has_ipv4_listener = any(ip.version == 4 for ip in listen_ips)
    rate_limiter = (ClientRateLimiter(args.rate_limit, args.rate_burst)
                    if args.rate_limit else None)
    stop = threading.Event()
    try:
        with ExitStack() as stack:
            capture = stack.enter_context(open_capture(args.learn_wan)) if args.learn_wan else None
            listeners = []
            for ip in listen_ips:
                address = (str(ip), args.port)
                family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
                listeners.append(stack.enter_context(
                    UdpServer(address, UdpHandler, authority, family, ipv6_only=has_ipv4_listener,
                              allowed_clients=allowed_clients, max_workers=args.max_workers,
                              rate_limiter=rate_limiter)))
                listeners.append(stack.enter_context(
                    TcpServer(address, TcpHandler, authority, family, ipv6_only=has_ipv4_listener,
                              allowed_clients=allowed_clients, max_workers=args.max_workers,
                              rate_limiter=rate_limiter)))
            for ip in dot_ips:
                address = (str(ip), args.dot_port)
                family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
                listeners.append(stack.enter_context(
                    DotServer(address, DotHandler, authority, family, ssl_context=dot_context,
                              ipv6_only=has_ipv4_listener or any(x.version == 4 for x in dot_ips),
                              allowed_clients=allowed_clients, max_workers=args.max_workers,
                              rate_limiter=rate_limiter)))
            if capture:
                watcher = threading.Thread(target=watch_wan, args=(capture, WanLearner(learned), stop), daemon=True)
                watcher.start()
                stack.callback(watcher.join, 1)
                logging.info("listening for DNS replies on WAN interface %s", args.learn_wan)
            if sources:
                downloader = threading.Thread(target=refresh_snapshots, args=(sources, stop), daemon=True)
                downloader.start()
                stack.callback(downloader.join, 1)
                logging.info("automatic DNS snapshot downloads enabled in %s", data_dir)
            stack.callback(stop.set)
            if rpz is not None:
                rpz_thread = threading.Thread(target=watch_rpz, args=(rpz, stop), daemon=True)
                rpz_thread.start()
                stack.callback(rpz_thread.join, 1)
            if args.resolve_wan:
                logging.info("direct authoritative lookups enabled via dig; DNS root queries disabled")
            for server in listeners[1:]:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                stack.callback(thread.join)
                stack.callback(server.shutdown)
            for ip in listen_ips:
                logging.info("authoritative DNS for %s on %s port %d (UDP and TCP)",
                             zone_names, ip, args.port)
            for ip in dot_ips:
                logging.info("DNS-over-TLS for %s on %s port %d (TCP)", zone_names, ip, args.dot_port)
            listeners[0].serve_forever()
    except KeyboardInterrupt:
        pass
    except PermissionError as error:
        parser.exit(1, f"permission denied: {error}. WAN capture needs CAP_NET_RAW.\n")
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
