"""Stability regressions for on-demand SQLite retention and local listeners."""
import concurrent.futures
from contextlib import closing
import importlib.util
import ipaddress
import socket
import sqlite3
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / 'src' / 'tekzite_dns.py'
spec = importlib.util.spec_from_file_location('tekzite_dns', SOURCE)
dns = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = dns
spec.loader.exec_module(dns)


class SQLiteRetentionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'cache.sqlite'
        self.authority = dns.Authority([dns.Zone(dns.EXAMPLE_ZONE)], dns.LearnedRecords(), ondemand_db=self.path)

    def test_prune_bounded_and_preserves_live_records(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            now = time.time()
            for i in range(1200):
                db.execute('INSERT INTO ondemand VALUES (?,?,?,?)', (f'{i}.example.org', 'A', '192.0.2.1', now - 10))
                db.execute('INSERT INTO ondemand_negative VALUES (?,?,?,?)', (f'{i}.example.org', 'A', 3, now - 10))
            db.execute('INSERT INTO ondemand VALUES (?,?,?,?)', ('live.example.org', 'A', '192.0.2.1', now + 1000))
            self.assertEqual(dns.prune_expired_ondemand(db, now), (500, 500))
            self.assertEqual(dns.prune_expired_ondemand(db, now), (500, 500))
            self.assertEqual(dns.prune_expired_ondemand(db, now), (200, 200))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM ondemand').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM ondemand_negative').fetchone()[0], 0)

    def test_prune_rejects_invalid_batch(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            with self.assertRaises(ValueError):
                dns.prune_expired_ondemand(db, time.time(), 0)

    def test_parallel_sqlite_writers_and_prune(self):
        now = time.time()
        def writer(i):
            with closing(sqlite3.connect(self.path, timeout=10)) as db, db:
                db.execute('INSERT OR REPLACE INTO ondemand VALUES (?,?,?,?)',
                           (f'{i}.example.org', 'A', '192.0.2.1', now - 1))
                self.authority.maybe_prune_ondemand(db)
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            list(pool.map(writer, range(300)))
        with closing(sqlite3.connect(self.path)) as db, db:
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM ondemand WHERE expires>?', (now,)).fetchone()[0], 0)
            self.assertLessEqual(db.execute('SELECT COUNT(*) FROM ondemand').fetchone()[0], 300)


class SocketLoadTests(unittest.TestCase):
    def test_udp_1000_queries_with_bounded_workers(self):
        authority = dns.Authority([dns.Zone(dns.EXAMPLE_ZONE)], dns.LearnedRecords())
        allowed = (ipaddress.ip_network('127.0.0.0/8'),)
        packet = struct.pack('!6H', 0xBEEF, dns.RD, 1, 0, 0, 0) + dns.Question(dns.domain('www.tekzite.test.'), dns.A).wire()
        with dns.UdpServer(('127.0.0.1', 0), dns.UdpHandler, authority,
                           allowed_clients=allowed, max_workers=32) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                def query(_):
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(2)
                        for attempt in range(4):
                            s.sendto(packet, server.server_address)
                            try:
                                reply, _ = s.recvfrom(4096)
                                return struct.unpack_from('!H', reply)[0] == 0xBEEF
                            except socket.timeout:
                                pass
                        return False
                with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                    results = list(pool.map(query, range(1000)))
                self.assertEqual(sum(results), 1000)
            finally:
                server.shutdown()
                thread.join(timeout=3)

    def test_tcp_100_queries(self):
        authority = dns.Authority([dns.Zone(dns.EXAMPLE_ZONE)], dns.LearnedRecords())
        allowed = (ipaddress.ip_network('127.0.0.0/8'),)
        packet = struct.pack('!6H', 0xBEEF, dns.RD, 1, 0, 0, 0) + dns.Question(dns.domain('www.tekzite.test.'), dns.A).wire()
        with dns.TcpServer(('127.0.0.1', 0), dns.TcpHandler, authority,
                           allowed_clients=allowed, max_workers=32) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                def query(_):
                    for attempt in range(4):
                        try:
                            with socket.create_connection(server.server_address, timeout=2) as s:
                                s.settimeout(2)
                                s.sendall(struct.pack('!H', len(packet)) + packet)
                                size = struct.unpack('!H', dns.receive_exact(s, 2, time.monotonic() + 2))[0]
                                reply = dns.receive_exact(s, size, time.monotonic() + 2)
                                return struct.unpack_from('!H', reply)[0] == 0xBEEF
                        except (OSError, EOFError):
                            continue
                    return False
                with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                    results = list(pool.map(query, range(100)))
                self.assertEqual(sum(results), 100)
            finally:
                server.shutdown()
                thread.join(timeout=3)


if __name__ == '__main__':
    unittest.main()
