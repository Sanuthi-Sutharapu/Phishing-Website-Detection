"""URL feature extraction for phishing detection.

Takes a raw URL string and returns a dict of numeric features. The SAME code
is used for building the training set and for live predictions, so there is
no gap between what the model learned on and what it sees in real use.

Only lexical / structural features here (v1). Host-based (WHOIS, DNS, SSL)
and page-content features are added in a later stage.
"""
import math
import re
from collections import Counter
from urllib.parse import urlparse

SUSPICIOUS_WORDS = (
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "password", "banking", "wallet", "webscr", "invoice", "billing",
    "support", "recover", "unlock", "suspend", "alert", "authenticate",
)
BRANDS = (
    "paypal", "apple", "google", "microsoft", "amazon", "facebook", "netflix",
    "instagram", "whatsapp", "onlinesbi", "hdfc", "icici", "paytm",
    "linkedin", "dropbox", "adobe", "office365", "outlook",
)
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at",
}
# Heuristic list of TLDs that are cheap/abused a lot. Not a rule, just a signal.
RISKY_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "icu", "cyou",
    "zip", "mov", "rest", "cfd", "sbs",
}
# Small list of two-part public suffixes (e.g. bank.co.in). Good enough for v1.
TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "org.in",
    "ac.in", "gov.in", "com.au", "net.au", "org.au", "co.jp", "com.br",
    "com.cn", "co.nz", "co.za", "com.sg", "com.mx",
}
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def _entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _split_host(host):
    """Return (subdomain_parts, registered_domain, suffix)."""
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 1:
        return [], host, ""
    suffix_len = 2 if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_SUFFIXES else 1
    suffix = ".".join(parts[-suffix_len:])
    registered = ".".join(parts[-(suffix_len + 1):])
    subdomains = parts[:-(suffix_len + 1)]
    return subdomains, registered, suffix


def extract_url_features(url):
    raw = (url or "").strip()
    has_scheme = bool(SCHEME_RE.match(raw))
    parse_target = raw if has_scheme else "http://" + raw
    try:
        parsed = urlparse(parse_target)
        host = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        scheme = parsed.scheme.lower() if has_scheme else ""
        try:
            port = parsed.port
        except ValueError:
            port = -1
    except ValueError:
        host, path, query, scheme, port = "", "", "", "", None

    bare = SCHEME_RE.sub("", raw)  # URL without scheme, so lengths aren't skewed
    bare_lower = bare.lower()

    is_ip = bool(IPV4_RE.match(host)) or ":" in host or bool(re.match(r"^0x[0-9a-f]+$", host))
    if is_ip:
        subdomains, registered, suffix = [], host, ""
    else:
        subdomains, registered, suffix = _split_host(host)

    text_for_brand = ".".join(subdomains) + " " + path.lower()
    brand_trick = any(b in text_for_brand and b not in registered for b in BRANDS)

    host_tokens = [t for t in re.split(r"[.\-]", host) if t]
    segments = [s for s in path.split("/") if s]
    n = max(len(bare), 1)

    return {
        "url_length": len(bare),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": bare.count("."),
        "num_hyphens_host": host.count("-"),
        "num_hyphens_url": bare.count("-"),
        "num_underscores": bare.count("_"),
        "num_slashes": bare.count("/"),
        "num_digits": sum(c.isdigit() for c in bare),
        "digit_ratio": sum(c.isdigit() for c in bare) / n,
        "num_digits_host": sum(c.isdigit() for c in host),
        "num_special_chars": sum(bare.count(c) for c in "@?&=%~#"),
        "has_at_symbol": int("@" in bare),
        "has_ip_host": int(is_ip),
        "has_nonstandard_port": int(port not in (None, 80, 443)),
        "is_https": int(scheme == "https"),
        "https_token_in_host": int("https" in host),
        "subdomain_depth": len(subdomains),
        "suffix_length": len(suffix),
        "risky_tld": int(suffix.split(".")[-1] in RISKY_TLDS) if suffix else 0,
        "has_punycode": int("xn--" in host),
        "is_shortener": int(registered in SHORTENERS),
        "suspicious_word_count": sum(w in bare_lower for w in SUSPICIOUS_WORDS),
        "brand_in_subdomain_or_path": int(brand_trick),
        "path_depth": len(segments),
        "num_query_params": (query.count("&") + 1) if query else 0,
        "double_slash_in_path": int("//" in path),
        "num_encoded_chars": len(re.findall(r"%[0-9a-fA-F]{2}", bare)),
        "longest_host_token": max((len(t) for t in host_tokens), default=0),
        "url_entropy": _entropy(bare_lower),
        "host_entropy": _entropy(host),
    }


FEATURE_NAMES = list(extract_url_features("http://example.com").keys())
