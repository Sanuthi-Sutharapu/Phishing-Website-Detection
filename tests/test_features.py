import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from features import extract_url_features as f, FEATURE_NAMES


class TestFeatures(unittest.TestCase):
    def test_ip_host(self):
        self.assertEqual(f("http://192.168.1.10/login")["has_ip_host"], 1)
        self.assertEqual(f("https://example.com/")["has_ip_host"], 0)

    def test_at_symbol(self):
        self.assertEqual(f("http://google.com@evil.example/x")["has_at_symbol"], 1)

    def test_brand_trick(self):
        self.assertEqual(f("http://paypal.com.secure-login.xyz/verify")["brand_in_subdomain_or_path"], 1)
        self.assertEqual(f("https://www.paypal.com/signin")["brand_in_subdomain_or_path"], 0)

    def test_subdomain_depth_and_two_part_suffix(self):
        self.assertEqual(f("https://a.b.example.com/")["subdomain_depth"], 2)
        self.assertEqual(f("https://www.bank.co.in/")["subdomain_depth"], 1)

    def test_https_and_risky_tld(self):
        self.assertEqual(f("https://example.com")["is_https"], 1)
        self.assertEqual(f("http://example.com")["is_https"], 0)
        self.assertEqual(f("http://free-prize.xyz")["risky_tld"], 1)

    def test_never_crashes_on_junk(self):
        for u in ["", "   ", "http://[bad", "not a url", "http://", "://x", None]:
            row = f(u)
            self.assertEqual(list(row.keys()), FEATURE_NAMES)


if __name__ == "__main__":
    unittest.main()
