"""Offline smoke and protocol tests for Tekzite DNS."""
import importlib.util
import json
import struct
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / 'src' / 'tekzite_dns.py'
spec = importlib.util.spec_from_file_location('tekzite_dns', SOURCE)
dns = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = dns
spec.loader.exec_module(dns)

class DNSProtocolTests(unittest.TestCase):
    def setUp(self):
        zone = dns.Zone(dns.EXAMPLE_ZONE)
        self.authority = dns.Authority([zone], dns.LearnedRecords())

    def query(self, name, kind=dns.A, flags=dns.RD):
        question = dns.Question(dns.domain(name), kind)
        return self.authority.handle(struct.pack('!6H', 0x1234, flags, 1, 0, 0, 0) + question.wire())

    def test_a_record(self):
        response = self.query('www.tekzite.test.')
        self.assertEqual(struct.unpack_from('!H', response, 2)[0] & 15, dns.OK)
        self.assertEqual(struct.unpack_from('!H', response, 6)[0], 1)

    def test_unknown_zone_refused(self):
        response = self.query('unrelated.example.')
        self.assertEqual(struct.unpack_from('!H', response, 2)[0] & 15, dns.REFUSED)

    def test_malformed_is_formerr(self):
        packet = struct.pack('!6H', 0x1234, dns.RD, 2, 0, 0, 0)
        self.assertEqual(struct.unpack_from('!H', self.authority.handle(packet), 2)[0] & 15, dns.FORMERR)

    def test_invalid_zone_config(self):
        self.assertRaises(ValueError, dns.Zone, {'origin': 'not a valid @ zone'})

if __name__ == '__main__':
    unittest.main()

class ClientAccessTests(unittest.TestCase):
    def test_loopback_default(self):
        import ipaddress
        allowed = [ipaddress.ip_network('127.0.0.0/8'), ipaddress.ip_network('::1/128')]
        self.assertTrue(dns.client_allowed('127.0.0.1', allowed))
        self.assertTrue(dns.client_allowed('::1', allowed))
        self.assertFalse(dns.client_allowed('192.168.50.100', allowed))
        self.assertFalse(dns.client_allowed('8.8.8.8', allowed))

    def test_ipv4_ipv6_lan_acl(self):
        import ipaddress
        allowed = [ipaddress.ip_network('192.168.50.0/24'),
                   ipaddress.ip_network('fd00:1234:5678::/64')]
        self.assertTrue(dns.client_allowed('192.168.50.199', allowed))
        self.assertFalse(dns.client_allowed('192.168.26.199', allowed))
        self.assertTrue(dns.client_allowed('fd00:1234:5678::42', allowed))
        self.assertFalse(dns.client_allowed('2001:db8::1', allowed))
        self.assertFalse(dns.client_allowed('invalid', allowed))

    def test_mapped_ipv4(self):
        import ipaddress
        allowed = [ipaddress.ip_network('192.168.50.0/24')]
        self.assertTrue(dns.client_allowed('::ffff:192.168.50.123', allowed))
        self.assertFalse(dns.client_allowed('::ffff:192.168.26.123', allowed))

class ListenerIntegrationTests(unittest.TestCase):
    def setUp(self):
        import ipaddress
        self.resolver = dns.Authority([dns.Zone(dns.EXAMPLE_ZONE)], dns.LearnedRecords())
        self.allowed = (ipaddress.ip_network('127.0.0.0/8'),)

    def test_udp_allowed(self):
        import socket
        import threading
        question = dns.Question(dns.domain('www.tekzite.test.'), dns.A)
        packet = struct.pack('!6H', 0x2345, dns.RD, 1, 0, 0, 0) + question.wire()
        with dns.UdpServer(('127.0.0.1', 0), dns.UdpHandler, self.resolver,
                           allowed_clients=self.allowed) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(2)
                    client.sendto(packet, server.server_address)
                    response, _ = client.recvfrom(2048)
                self.assertEqual(struct.unpack_from('!H', response, 0)[0], 0x2345)
                self.assertEqual(struct.unpack_from('!H', response, 6)[0], 1)
            finally:
                server.shutdown()
                thread.join(timeout=2)

    def test_tcp_allowed(self):
        import socket
        import threading
        question = dns.Question(dns.domain('www.tekzite.test.'), dns.A)
        packet = struct.pack('!6H', 0x3456, dns.RD, 1, 0, 0, 0) + question.wire()
        with dns.TcpServer(('127.0.0.1', 0), dns.TcpHandler, self.resolver,
                           allowed_clients=self.allowed) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with socket.create_connection(server.server_address, timeout=2) as client:
                    client.settimeout(2)
                    client.sendall(struct.pack('!H', len(packet)) + packet)
                    size = struct.unpack('!H', dns.receive_exact(client, 2, __import__('time').monotonic() + 2))[0]
                    response = dns.receive_exact(client, size, __import__('time').monotonic() + 2)
                self.assertEqual(struct.unpack_from('!H', response, 0)[0], 0x3456)
                self.assertEqual(struct.unpack_from('!H', response, 6)[0], 1)
            finally:
                server.shutdown()
                thread.join(timeout=2)

    def test_udp_rejected_client(self):
        import ipaddress
        import socket
        import threading
        allowed = (ipaddress.ip_network('192.0.2.0/24'),)
        with dns.UdpServer(('127.0.0.1', 0), dns.UdpHandler, self.resolver,
                           allowed_clients=allowed) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(0.2)
                    client.sendto(b'blocked', server.server_address)
                    with self.assertRaises(socket.timeout):
                        client.recvfrom(2048)
            finally:
                server.shutdown()
                thread.join(timeout=2)

class ProtocolHardeningTests(unittest.TestCase):
    def setUp(self):
        self.resolver = dns.Authority([dns.Zone(dns.EXAMPLE_ZONE)], dns.LearnedRecords())
        self.qwire = dns.Question(dns.domain('www.tekzite.test.'), dns.A).wire()

    def packet(self, *, flags=dns.RD, qd=1, an=0, ns=0, ar=0, suffix=b''):
        return struct.pack('!6H', 0x5A5A, flags, qd, an, ns, ar) + self.qwire + suffix

    def rcode(self, packet):
        response = self.resolver.handle(packet)
        self.assertIsNotNone(response)
        self.assertEqual(struct.unpack_from('!H', response)[0], 0x5A5A)
        return struct.unpack_from('!H', response, 2)[0] & 15

    def opt(self, data=b'', *, flags=0, version=0, udp_size=1232):
        ttl = (version << 16) | flags
        return b'\0' + struct.pack('!HHIH', dns.OPT, udp_size, ttl, len(data)) + data

    def test_reserved_header_bit_rejected(self):
        self.assertEqual(self.rcode(self.packet(flags=dns.RD | 0x0040)), dns.FORMERR)

    def test_ad_cd_bits_do_not_count_as_reserved(self):
        self.assertEqual(self.rcode(self.packet(flags=dns.RD | 0x0030)), dns.OK)

    def test_valid_edns_options_including_unknown_accepted(self):
        payload = struct.pack('!HH', 65001, 3) + b'xyz'
        self.assertEqual(self.rcode(self.packet(ar=1, suffix=self.opt(payload))), dns.OK)

    def test_edns_truncated_option_header(self):
        for data in (b'\0', b'\0\1', b'\0\1\0'):
            with self.subTest(data=data):
                self.assertEqual(self.rcode(self.packet(ar=1, suffix=self.opt(data))), dns.FORMERR)

    def test_edns_truncated_option_payload(self):
        data = struct.pack('!HH', 10, 5) + b'abc'
        self.assertEqual(self.rcode(self.packet(ar=1, suffix=self.opt(data))), dns.FORMERR)

    def test_reserved_edns_flag_rejected(self):
        self.assertEqual(self.rcode(self.packet(ar=1, suffix=self.opt(flags=1))), dns.FORMERR)

    def test_edns_do_bit_accepted(self):
        self.assertEqual(self.rcode(self.packet(ar=1, suffix=self.opt(flags=0x8000))), dns.OK)

    def test_edns_version_negotiation(self):
        response = self.resolver.handle(self.packet(ar=1, suffix=self.opt(version=1)))
        self.assertEqual(struct.unpack_from('!H', response, 10)[0], 1)
        # BADVERS has an extended RCODE in the response OPT record.
        _, offset = dns.read_question(response)
        _, _, additional = dns.read_sections(response, offset, (0, 0, 1))
        self.assertEqual(additional[0].ttl >> 24, 1)

    def test_duplicate_edns_opt_rejected(self):
        self.assertEqual(self.rcode(self.packet(ar=2, suffix=self.opt() * 2)), dns.FORMERR)

    def test_trailing_bytes_rejected(self):
        self.assertEqual(self.rcode(self.packet(suffix=b'extra')), dns.FORMERR)

    def test_compression_forward_pointer_rejected(self):
        packet = struct.pack('!6H', 0x5A5A, dns.RD, 1, 0, 0, 0) + b'\xc0\x0e' + struct.pack('!HH', dns.A, dns.IN)
        self.assertEqual(self.rcode(packet), dns.FORMERR)

    def test_compression_self_pointer_rejected(self):
        packet = struct.pack('!6H', 0x5A5A, dns.RD, 1, 0, 0, 0) + b'\xc0\x0c' + struct.pack('!HH', dns.A, dns.IN)
        self.assertEqual(self.rcode(packet), dns.FORMERR)

    def test_random_payloads_do_not_raise(self):
        import random
        rng = random.Random(0x7E2)
        for _ in range(1000):
            packet = bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 512)))
            response = self.resolver.handle(packet)
            self.assertTrue(response is None or isinstance(response, bytes))

    def test_truncated_real_query_is_safe(self):
        complete = self.packet(ar=1, suffix=self.opt(struct.pack('!HH', 10, 8) + b'12345678'))
        for n in range(len(complete)):
            response = self.resolver.handle(complete[:n])
            self.assertTrue(response is None or isinstance(response, bytes))

    def test_mutated_query_frames_do_not_raise(self):
        import random
        rng = random.Random(20261111)
        base = self.packet(ar=1, suffix=self.opt(struct.pack('!HH', 65000, 3) + b'abc'))
        for _ in range(1000):
            packet = bytearray(base)
            for _ in range(rng.randint(1, 8)):
                if packet:
                    packet[rng.randrange(len(packet))] = rng.randrange(256)
            response = self.resolver.handle(bytes(packet))
            self.assertTrue(response is None or isinstance(response, bytes))

class ResourceHardeningTests(unittest.TestCase):
    def test_token_bucket_burst_refill_and_isolation(self):
        limiter = dns.ClientRateLimiter(rate=2, burst=3)
        self.assertEqual([limiter.allow('192.0.2.1', now=10) for _ in range(4)],
                         [True, True, True, False])
        self.assertTrue(limiter.allow('192.0.2.2', now=10))
        self.assertTrue(limiter.allow('192.0.2.1', now=10.5))
        self.assertFalse(limiter.allow('192.0.2.1', now=10.5))
        self.assertTrue(limiter.allow('192.0.2.1', now=11))

    def test_bucket_cannot_be_reset_by_mapped_ipv4(self):
        limiter = dns.ClientRateLimiter(rate=1, burst=1)
        self.assertTrue(limiter.allow('192.0.2.1', now=10))
        self.assertFalse(limiter.allow('::ffff:192.0.2.1', now=10))
        self.assertFalse(limiter.allow('not-an-ip', now=10))

    def test_bounded_peer_tracking_and_expiration(self):
        limiter = dns.ClientRateLimiter(rate=1, burst=1, max_clients=2, idle_seconds=10)
        self.assertTrue(limiter.allow('192.0.2.1', now=1))
        self.assertTrue(limiter.allow('192.0.2.2', now=1))
        self.assertFalse(limiter.allow('192.0.2.3', now=2))
        self.assertEqual(len(limiter.buckets), 2)
        self.assertTrue(limiter.allow('192.0.2.3', now=12))
        self.assertEqual(len(limiter.buckets), 1)

    def test_invalid_limits(self):
        for rate, burst, max_clients in [(0, 1, 2), (1, 0, 2), (1, 1, 0)]:
            with self.assertRaises(ValueError):
                dns.ClientRateLimiter(rate, burst, max_clients)

    def test_server_rate_limit_rejects_second_udp_packet(self):
        import socket
        import threading
        import ipaddress
        resolver = dns.Authority([dns.Zone(dns.EXAMPLE_ZONE)], dns.LearnedRecords())
        question = dns.Question(dns.domain('www.tekzite.test.'), dns.A)
        packet = struct.pack('!6H', 0x2345, dns.RD, 1, 0, 0, 0) + question.wire()
        with dns.UdpServer(('127.0.0.1', 0), dns.UdpHandler, resolver,
                           allowed_clients=(ipaddress.ip_network('127.0.0.0/8'),),
                           rate_limiter=dns.ClientRateLimiter(0.01, 1)) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(1)
                    client.sendto(packet, server.server_address)
                    self.assertEqual(client.recvfrom(2048)[0][:2], packet[:2])
                    client.sendto(packet, server.server_address)
                    client.settimeout(0.3)
                    with self.assertRaises(socket.timeout):
                        client.recvfrom(2048)
            finally:
                server.shutdown()
                worker.join(timeout=2)

    def test_parallel_udp_load(self):
        import concurrent.futures
        import socket
        import threading
        import ipaddress
        resolver = dns.Authority([dns.Zone(dns.EXAMPLE_ZONE)], dns.LearnedRecords())
        question = dns.Question(dns.domain('www.tekzite.test.'), dns.A)
        with dns.UdpServer(('127.0.0.1', 0), dns.UdpHandler, resolver,
                           allowed_clients=(ipaddress.ip_network('127.0.0.0/8'),),
                           max_workers=32) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            def query(index):
                packet = struct.pack('!6H', index, dns.RD, 1, 0, 0, 0) + question.wire()
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(2)
                    client.sendto(packet, server.server_address)
                    return client.recvfrom(2048)[0][:2] == packet[:2]
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                    successes = list(pool.map(query, range(100)))
                self.assertEqual(sum(successes), 100)
            finally:
                server.shutdown()
                worker.join(timeout=2)
