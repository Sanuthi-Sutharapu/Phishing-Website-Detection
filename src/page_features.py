"""Content-based features from a page's HTML.

Pure function: HTML text in, dict of numbers out. Nothing is executed and
nothing is downloaded here, so it is safe to unit-test on plain strings.
The fetching itself lives in fetch_pages.py.
"""
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from features import BRANDS, _split_host

LOGIN_WORDS = (
    "sign in", "log in", "login", "password", "verify", "account", "confirm",
    "security", "update your", "suspended", "unusual activity",
)
NON_HTTP_PREFIXES = ("#", "javascript:", "mailto:", "tel:", "data:", "about:")


def registered_domain(url_or_host):
    text = str(url_or_host or "")
    host = urlparse(text if "://" in text else "http://" + text).hostname or ""
    host = host.lower()
    return _split_host(host)[1] or host


def extract_page_features(html, page_url):
    soup = BeautifulSoup(html or "", "html.parser")
    page_dom = registered_domain(page_url)

    def is_external(u):
        u = (u or "").strip()
        if not u or u.lower().startswith(NON_HTTP_PREFIXES):
            return False
        full = urljoin(page_url, u)
        host = urlparse(full).hostname
        return bool(host) and registered_domain(full) != page_dom

    # Forms and inputs
    forms = soup.find_all("form")
    inputs = soup.find_all("input")
    n_password = sum((i.get("type") or "").lower() == "password" for i in inputs)
    actions = [(f.get("action") or "").strip() for f in forms]
    form_action_external = any(is_external(a) for a in actions)
    form_action_empty = any(a in ("", "#", "about:blank") or a.lower().startswith("javascript") for a in actions)
    form_action_mailto = any(a.lower().startswith("mailto:") for a in actions)

    # Links
    hrefs = [(a.get("href") or "").strip() for a in soup.find_all("a")]
    n_links = len(hrefs)
    empty_links = sum(h in ("", "#") or h.lower().startswith("javascript") for h in hrefs)
    ext_links = sum(is_external(h) for h in hrefs)

    # Embedded resources (images, scripts, iframes, stylesheets)
    resources = [t.get("src") for t in soup.find_all(["img", "script", "iframe"]) if t.get("src")]
    resources += [t.get("href") for t in soup.find_all("link") if t.get("href")]
    ext_resources = sum(is_external(r) for r in resources)
    icons = [
        t.get("href") for t in soup.find_all("link")
        if t.get("href") and "icon" in " ".join(t.get("rel") or []).lower()
    ]

    # Iframes, redirects and shady scripting habits
    iframes = soup.find_all("iframe")
    hidden_iframe = any(
        re.search(r"display\s*:\s*none|visibility\s*:\s*hidden", (f.get("style") or ""), re.I)
        or (f.get("width") or "").strip() in ("0", "1")
        or (f.get("height") or "").strip() in ("0", "1")
        for f in iframes
    )
    meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)}) is not None
    scripts = soup.find_all("script")
    script_text = " ".join(s.get_text() for s in scripts)
    html_lower = (html or "").lower()

    title = soup.title.get_text(strip=True) if soup.title else ""
    title_brand_mismatch = any(b in title.lower() and b not in page_dom for b in BRANDS)

    # Visible text (drop scripts and styles first)
    for t in soup(["script", "style", "noscript"]):
        t.decompose()
    text = soup.get_text(" ", strip=True).lower()

    return {
        "html_length": len(html or ""),
        "text_length": len(text),
        "title_length": len(title),
        "title_brand_mismatch": int(title_brand_mismatch),
        "num_forms": len(forms),
        "num_input_fields": len(inputs),
        "num_password_inputs": n_password,
        "has_password_input": int(n_password > 0),
        "form_action_external": int(form_action_external),
        "form_action_empty": int(form_action_empty),
        "form_action_mailto": int(form_action_mailto),
        "num_links": n_links,
        "external_link_ratio": ext_links / max(n_links, 1),
        "empty_link_ratio": empty_links / max(n_links, 1),
        "external_resource_ratio": ext_resources / max(len(resources), 1),
        "favicon_external": int(any(is_external(h) for h in icons)),
        "num_scripts": len(scripts),
        "num_iframes": len(iframes),
        "has_hidden_iframe": int(hidden_iframe),
        "has_meta_refresh": int(meta_refresh),
        "right_click_disabled": int("contextmenu" in html_lower),
        "num_onmouseover": html_lower.count("onmouseover"),
        "uses_window_open": int("window.open(" in script_text.lower()),
        "login_word_count": sum(w in text for w in LOGIN_WORDS),
    }


PAGE_FEATURE_NAMES = list(extract_page_features("<html></html>", "http://example.com").keys())
