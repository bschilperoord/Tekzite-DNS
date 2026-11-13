"""Native DNS-over-TLS tests using temporary local certificates."""
import importlib.util
import ipaddress
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'src' / 'tekzite_dns.py'
spec = importlib.util.spec_from_file_location('tekzite_dns', SOURCE)
dns = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = dns
spec.loader.exec_module(dns)

@unittest.skipUnless(shutil.which('openssl'), 'requires local openssl binary')
class DNSOverTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        directory = Path(cls.tempdir.name)
        cls.key = directory / 'key.pem'
        cls.cert = directory / 'cert.pem'
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'ec',
            '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
            '-keyout', str(cls.key), '-out', str(cls.cert),
            '-days', '1', '-subj', '/CN=dot.test',
            '-addext', 'subjectAltName=DNS:dot.test'
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        cls.trust = ssl.create_default_context(cafile=str(cls.cert))
        cls.trust.minimum_version = ssl.TLSVersion.TLSv1_2
        cls.authority = dns.Authority([dns.Zone(dns.EXAMPLE_ZONE)], dns.LearnedRecords())
        cls.server = dns.DotServer(
            ('127.0.0.1', 0), dns.DotHandler, cls.authority, ssl_context=dns.build_dot_context(cls.cert, cls.key),
            allowed_clients=(ipaddress.ip_network('127.0.0.0/8'),), max_workers=8
        )
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=3)
        cls.tempdir.cleanup()

    @staticmethod
    def packet(txid=0xDB53):
        return (struct.pack('!6H', txid, dns.RD, 1, 0, 0, 0)
                + dns.Question(dns.domain('www.tekzite.test.'), dns.A).wire())

    def test_tls_dns_exchange(self):
        with socket.create_connection(self.server.server_address, timeout=3) as raw:
            with self.trust.wrap_socket(raw, server_hostname='dot.test') as connection:
                self.assertIn(connection.version(), ('TLSv1.2', 'TLSv1.3'))
                connection.settimeout(3)
                pkt = self.packet()
                connection.sendall(struct.pack('!H', len(pkt)) + pkt)
                size = struct.unpack('!H', dns.receive_exact(connection, 2, time.monotonic() + 3))[0]
                response = dns.receive_exact(connection, size, time.monotonic() + 3)
                self.assertEqual(struct.unpack_from('!H', response)[0], 0xDB53)
                self.assertEqual(struct.unpack_from('!H', response, 6)[0], 1)

    def test_multi_query_session(self):
        with socket.create_connection(self.server.server_address, timeout=3) as raw:
            with self.trust.wrap_socket(raw, server_hostname='dot.test') as connection:
                for txid in range(5):
                    packet = self.packet(txid)
                    connection.sendall(struct.pack('!H', len(packet)) + packet)
                    n = struct.unpack('!H', dns.receive_exact(connection, 2, time.monotonic() + 3))[0]
                    answer = dns.receive_exact(connection, n, time.monotonic() + 3)
                    self.assertEqual(struct.unpack_from('!H', answer)[0], txid)

    def test_wrong_hostname_is_rejected(self):
        with socket.create_connection(self.server.server_address, timeout=3) as raw:
            with self.assertRaises(ssl.SSLCertVerificationError):
                with self.trust.wrap_socket(raw, server_hostname='another.test'):
                    pass

    def test_plaintext_is_not_dns(self):
        with socket.create_connection(self.server.server_address, timeout=3) as raw:
            raw.settimeout(2)
            packet = self.packet()
            raw.sendall(struct.pack('!H', len(packet)) + packet)
            try:
                response = raw.recv(512)
            except (ConnectionResetError, socket.timeout):
                response = b''
            self.assertFalse(response.startswith(struct.pack('!H', len(packet))))
            self.assertNotIn(struct.pack('!H', 0xDB53), response[:4])

    def test_client_allowlist_denial(self):
        restricted = dns.DotServer(
            ('127.0.0.1', 0), dns.DotHandler, self.authority,
            ssl_context=dns.build_dot_context(self.cert, self.key),
            allowed_clients=(ipaddress.ip_network('192.0.2.0/24'),), max_workers=2
        )
        thread = threading.Thread(target=restricted.serve_forever, daemon=True)
        thread.start()
        try:
            with socket.create_connection(restricted.server_address, timeout=2) as raw:
                raw.settimeout(2)
                with self.assertRaises((OSError, ssl.SSLError, EOFError)):
                    with self.trust.wrap_socket(raw, server_hostname='dot.test'):
                        pass
        finally:
            restricted.shutdown()
            restricted.server_close()
            thread.join(timeout=3)

    def test_bad_key_fails_closed(self):
        with self.assertRaises((ssl.SSLError, OSError)):
            dns.build_dot_context(self.cert, self.cert)

if __name__ == '__main__':
    unittest.main()
