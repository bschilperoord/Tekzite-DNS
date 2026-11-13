"""Regression tests for DNS HTTPS (65) and SVCB (64) support."""
import importlib.util
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import dns.message
import dns.resolver
import dns.rrset

SOURCE = Path(__file__).resolve().parents[1] / "src" / "tekzite_dns.py"
spec = importlib.util.spec_from_file_location("tekzite_dns", SOURCE)
dns_server = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = dns_server
spec.loader.exec_module(dns_server)


class HTTPSRecordTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.db = str(Path(self.temporary.name) / "cache.db")
        self.authority = dns_server.Authority(
            [dns_server.Zone(dns_server.EXAMPLE_ZONE)],
            dns_server.LearnedRecords(),
            ondemand_db=self.db,
        )
        self.question = dns_server.Question(dns_server.domain("cloudflare.com."), dns_server.HTTPS)

    def upstream(self, record_type="HTTPS", value='1 . alpn="h2" ech="AQIDBA=="'):
        query = dns.message.make_query("cloudflare.com.", record_type)
        response = dns.message.make_response(query)
        response.answer.append(dns.rrset.from_text("cloudflare.com.", 120, "IN", record_type, value))
        resolver = Mock()
        resolver.resolve.return_value = Mock(response=response)
        return resolver

    def test_https_includes_ech(self):
        resolver = self.upstream()
        with patch("dns.resolver.Resolver", return_value=resolver):
            reply = self.authority.answer(self.question, True)
        self.assertEqual(reply.code, dns_server.OK)
        self.assertEqual(reply.answers[0].kind, dns_server.HTTPS)
        self.assertIn(b"\x00\x05", reply.answers[0].data)  # ECH SvcParamKey

    def test_https_is_not_refused(self):
        with patch("dns.resolver.Resolver", return_value=self.upstream()):
            self.assertEqual(self.authority.answer(self.question, True).code, dns_server.OK)

    def test_sqlite_cache_survives_new_authority(self):
        resolver = self.upstream()
        with patch("dns.resolver.Resolver", return_value=resolver):
            self.authority.answer(self.question, True)
        second = dns_server.Authority(
            [dns_server.Zone(dns_server.EXAMPLE_ZONE)],
            dns_server.LearnedRecords(),
            ondemand_db=self.db,
        )
        with patch("dns.resolver.Resolver", side_effect=AssertionError("upstream used")):
            self.assertEqual(second.answer(self.question, True).code, dns_server.OK)

    def test_no_answer_is_not_refused(self):
        resolver = self.upstream()
        resolver.resolve.side_effect = dns.resolver.NoAnswer()
        with patch("dns.resolver.Resolver", return_value=resolver):
            self.assertEqual(self.authority.answer(self.question, True).code, dns_server.OK)

    def test_svcb_type64(self):
        query = dns_server.Question(dns_server.domain("cloudflare.com."), dns_server.SVCB)
        with patch("dns.resolver.Resolver", return_value=self.upstream("SVCB")):
            reply = self.authority.answer(query, True)
        self.assertEqual(reply.answers[0].kind, dns_server.SVCB)


if __name__ == "__main__":
    unittest.main()
