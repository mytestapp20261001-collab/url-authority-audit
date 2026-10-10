import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("url_audit_tool", ROOT / "tool.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

class AuditTests(unittest.TestCase):
    def run_audit(self, *urls):
        return tool.audit({"urls": list(urls)})
    def codes(self, result):
        return [item["code"] for item in result["findings"]]
    def test_good(self):
        self.assertEqual(self.run_audit("https://Example.COM/path?q=a#f")["status"], "pass")
    def test_empty_query_fragment_presence(self):
        item = self.run_audit("https://example.com/?#")["urls"][0]
        self.assertTrue(item["query_present"])
        self.assertTrue(item["fragment_present"])
    def test_default_ports(self):
        r = self.run_audit("http://example.com", "https://example.com:443", "https://example.com:65535")
        self.assertEqual([x["effective_port"] for x in r["urls"]], [80, 443, 65535])
    def test_ipv4_ipv6(self):
        r = self.run_audit("http://192.0.2.1", "https://[2001:0db8::1]:8443")
        self.assertEqual([x["host_kind"] for x in r["urls"]], ["ipv4", "ipv6"])
        self.assertEqual(r["urls"][1]["origin"], "https://[2001:db8::1]:8443")
    def test_credentials_redaction(self):
        r = self.run_audit("https://secret-user:secret-pass@example.com/a?secret-query#secret-fragment")
        output = json.dumps(r)
        for secret in ["secret-user", "secret-pass", "secret-query", "secret-fragment"]:
            self.assertNotIn(secret, output)
        self.assertIn("userinfo_present", self.codes(r))
    def test_parse_failure_redaction(self):
        r = self.run_audit("https://secret-user:secret-pass@[invalid/?secret-query")
        self.assertNotIn("secret", json.dumps(r))
        self.assertIn("url_parse_error", self.codes(r))
    def test_idna(self):
        r = self.run_audit("https://bücher.example", "https://xn--bcher-kva.example")
        self.assertEqual([x["host"] for x in r["urls"]], ["xn--bcher-kva.example"] * 2)
        self.assertEqual(self.codes(r), ["unicode_idna_mapping"])
    def test_idna2003_mapping(self):
        r = self.run_audit("https://faß.example")
        self.assertEqual(r["urls"][0]["host"], "fass.example")
        self.assertIn("unicode_idna_mapping", self.codes(r))
    def test_invalid_hosts(self):
        for url in ["https://a_b.example", "https://-bad.example", "https://a..example", "https://xn--.example", "https://%65xample.com", "https://" + "a" * 64 + ".com"]:
            with self.subTest(url=url):
                self.assertEqual(self.run_audit(url)["status"], "fail")
    def test_numeric_ambiguity(self):
        for host in ["2130706433", "0x", "example.0x", "127.1", "0177.0.0.1", "0x7f000001", "example.123", "999.1.1.1"]:
            self.assertIn("numeric_host_ambiguity", self.codes(self.run_audit("https://" + host)))
    def test_ports(self):
        for suffix, code in [(":", "empty_port"), (":0", "zero_port"), (":00080", "noncanonical_port"), (":65536", "invalid_host_or_port"), (":word", "invalid_host_or_port")]:
            self.assertIn(code, self.codes(self.run_audit("http://example.com" + suffix)))
    def test_userinfo_multiple_at(self):
        self.assertIn("multiple_at_ambiguity", self.codes(self.run_audit("http://a@b@example.com")))
    def test_whitespace_backslash(self):
        self.assertIn("whitespace_or_control", self.codes(self.run_audit(" \thttps://example.com")))
        self.assertIn("backslash_ambiguity", self.codes(self.run_audit("https://example.com\\@evil.example")))
    def test_scheme_authority(self):
        for url in ["//example.com", "/path", "https:example.com", "ftp://example.com"]:
            self.assertEqual(self.run_audit(url)["status"], "fail")
    def test_ipv6_scope_future_and_suffix(self):
        for url in ["https://[fe80::1%25eth0]", "https://[v1.test]", "https://[::1]suffix", "https://2001:db8::1"]:
            self.assertEqual(self.run_audit(url)["status"], "fail")
    def test_trailing_dot(self):
        r = self.run_audit("https://example.com.")
        self.assertEqual(r["urls"][0]["host"], "example.com.")
        self.assertIn("trailing_dot_host", self.codes(r))
    def test_nfkc_delimiters(self):
        self.assertIn("url_parse_error", self.codes(self.run_audit("https://example.com\uff0fsecret")))
    def test_schema_limits(self):
        for data in [{}, {"urls": []}, {"urls": [1]}, {"urls": ["x" * 8193]}, {"urls": ["x"] * 257}, {"urls": ["x"], "unknown": True}]:
            self.assertEqual(tool.audit(data)["status"], "error")
        self.assertEqual(self.run_audit(*(["https://example.com"] * 256))["status"], "pass")
    def test_findings_truncated(self):
        r = self.run_audit(*([" http://user@127.1:"] * 256))
        self.assertTrue(r["findings_truncated"])
        self.assertEqual(len(r["findings"]), 500)
    def test_stable(self):
        self.assertEqual(self.run_audit("https://example.com"), self.run_audit("https://example.com"))
    def cli(self, raw, *args):
        return subprocess.run([sys.executable, str(ROOT / "tool.py"), *args], input=raw, text=True, capture_output=True)
    def test_cli_exit_codes(self):
        for raw, code in [('{"urls":["https://example.com"]}', 0), ('{"urls":["bad"]}', 1), ('{}', 2)]:
            r = self.cli(raw)
            self.assertEqual(r.returncode, code, r.stderr)
            json.loads(r.stdout)
    def test_cli_examples(self):
        for name, code in [("good", 0), ("bad", 1)]:
            self.assertEqual(self.cli("", "--input", str(ROOT / "examples" / (name + ".json"))).returncode, code)
    def test_cli_error_privacy(self):
        for args in [("--bad", "secret-user"), ("--input", "/missing/secret-user")]:
            r = self.cli("", *args)
            self.assertEqual(r.returncode, 2)
            self.assertNotIn("secret-user", r.stdout + r.stderr)
        for raw in ['{"urls":[],"urls":[]}', '{"urls":NaN}', '{', ' ' * (tool.MAX_BYTES + 1)]:
            self.assertEqual(self.cli(raw).returncode, 2)

    def test_cli_exact_byte_boundary(self):
        valid = '{"urls":["https://example.com"]}'
        self.assertEqual(self.cli(valid + " " * (tool.MAX_BYTES - len(valid))).returncode, 0)
    def test_cli_invalid_utf8_and_deep_json(self):
        result = subprocess.run([sys.executable, str(ROOT / "tool.py")], input=b"\xff", capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b"Traceback", result.stderr)
        self.assertEqual(self.cli("[" * 1500 + "]" * 1500).returncode, 2)
    def test_nonregular_input_file(self):
        result = self.cli("", "--input", str(ROOT))
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(str(ROOT), result.stdout + result.stderr)

if __name__ == "__main__":
    unittest.main()
