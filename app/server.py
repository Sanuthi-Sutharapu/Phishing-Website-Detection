"""Hook or Not - local web app.

Run from the project folder (after train.py has created models/model.joblib):
    pip install flask requests
    python app/server.py          then open http://127.0.0.1:5000

Optional (catches brand-new phishing the model has never seen), PowerShell:
    $env:GOOGLE_SAFE_BROWSING_KEY="your-key"
With a key, the address you check is sent to Google's Safe Browsing service.

Layers, in order: your collected phishing lists -> Google Safe Browsing (if key)
-> popular-domain list -> the trained model. No detector is right on every link.
The server never visits the URL you enter.
"""
import os
import random
import sys
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd
import requests
from flask import Flask, jsonify, request, send_from_directory

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from features import SCHEME_RE, SUSPICIOUS_WORDS, extract_url_features, _split_host  # noqa: E402

bundle = joblib.load(ROOT / "models" / "model.joblib")
MODEL, FEATURES = bundle["model"], bundle["features"]
SUSPICIOUS_AT, PHISHING_AT = 0.50, 0.80  # from analyze.py: 0.80 kept false positives near 1%
RAW = ROOT / "data" / "raw"
SB_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "")
# Shared platforms where anyone can host a page: never treat these as "popular = safe".
SHARED_HOSTS = {"pages.dev", "github.io", "netlify.app", "vercel.app", "webflow.io", "weebly.com",
                "blogspot.com", "wixsite.com", "herokuapp.com", "web.app", "firebaseapp.com", "glitch.me",
                "workers.dev", "azurewebsites.net", "amazonaws.com", "sites.google.com", "wordpress.com"}


def read_lines(path):
    if not path.exists():
        return []
    return [ln.strip() for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]


def host_of(url):
    try:
        return (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    except ValueError:
        return ""


def key_of(url):
    return url.strip().rstrip("/").lower()


PHISH_URLS = set()
for p in RAW.glob("openphish*.txt"):
    PHISH_URLS.update(read_lines(p))
for p in RAW.glob("phishtank*.csv"):
    try:
        PHISH_URLS.update(pd.read_csv(p)["url"].dropna().astype(str))
    except Exception:
        pass
PHISH_KEYS = {key_of(u) for u in PHISH_URLS}
PHISH_HOSTS = {host_of(u) for u in PHISH_URLS} - {""}
LEGIT_URLS = read_lines(RAW / "legit_urls.txt")
TOP = {ln.split(",")[1] for ln in read_lines(RAW / "tranco_top.csv")[:20000] if "," in ln}
print(f"Loaded {len(PHISH_URLS)} known phishing URLs, {len(LEGIT_URLS)} legit URLs, "
      f"{len(TOP)} popular domains. Safe Browsing: {'on' if SB_KEY else 'off'}")

STATIC = Path(__file__).resolve().parent / "static"
app = Flask(__name__, static_folder=str(STATIC))


def explain(url, f):
    reasons = []

    def add(level, text):
        reasons.append({"level": level, "text": text})

    if f["has_ip_host"]:
        add("high", "Uses a raw IP address instead of a domain name.")
    if f["has_at_symbol"]:
        add("high", "Contains an @ sign, which can hide the real destination.")
    if f["has_punycode"]:
        add("high", "Uses look-alike (punycode) characters in the domain.")
    if f["brand_in_subdomain_or_path"]:
        add("high", "Names a well-known brand, but the real domain belongs to someone else.")
    if f["risky_tld"]:
        add("medium", "Ends in a domain type that phishing sites often use.")
    if f["subdomain_depth"] >= 3:
        add("medium", f"Has {f['subdomain_depth']} subdomain levels, a common way to fake a real address.")
    if f["num_hyphens_host"] >= 2:
        add("medium", "The domain name contains several hyphens.")
    words = [w for w in SUSPICIOUS_WORDS if w in url.lower()]
    if len(words) >= 2:
        add("medium", "Contains sensitive words: " + ", ".join(words[:4]) + ".")
    if f["is_shortener"]:
        add("medium", "A link shortener hides where this really goes.")
    if f["https_token_in_host"]:
        add("medium", "Puts the word 'https' inside the domain to look secure.")
    if f["has_nonstandard_port"]:
        add("medium", "Uses an unusual network port.")
    if f["url_length"] > 90:
        add("low", "The address is unusually long.")
    if not f["is_https"]:
        add("low", "The connection is not encrypted (http).")
    return reasons


def url_parts(url, is_ip):
    """Split a URL into display chunks so the page can highlight the real domain."""
    host = host_of(url)
    idx = url.lower().find(host) if host else -1
    if idx < 0:
        return None
    subs, domain, _ = ([], host, "") if is_ip else _split_host(host)
    return {"scheme": url[:idx], "subdomain": ".".join(subs) + "." if subs else "",
            "domain": domain or host, "rest": url[idx + len(host):]}


def safe_browsing_hit(url):
    if not SB_KEY:
        return False
    body = {"client": {"clientId": "hook-or-not", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": ["SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                           "threatEntries": [{"url": url}]}}
    try:
        r = requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                          params={"key": SB_KEY}, json=body, timeout=4)
        return bool(r.ok and r.json().get("matches"))
    except Exception:
        return False


def verdict_of(score):
    return "phishing" if score >= PHISHING_AT else "suspicious" if score >= SUSPICIOUS_AT else "legitimate"


@app.get("/")
def index():
    return send_from_directory(STATIC, "index.html")


@app.post("/api/check")
def check():
    body = request.get_json(silent=True) or {}
    url = str(body.get("url", "")).strip()
    game = bool(body.get("game") or body.get("model_only"))  # game mode: model only, so it can't look answers up
    if not url or len(url) > 2000 or any(c.isspace() for c in url):
        return jsonify(error="Enter a full web address without spaces, like https://example.com/page"), 400
    assumed_https = not SCHEME_RE.match(url)
    if assumed_https:
        url = "https://" + url

    f = extract_url_features(url)
    score = float(MODEL.predict_proba(pd.DataFrame([f])[FEATURES])[0][1])
    reasons = explain(url, f)
    host = host_of(url)
    reg = _split_host(host)[1] or host

    if not game:
        if key_of(url) in PHISH_KEYS or host in PHISH_HOSTS:
            score = 1.0
            reasons.insert(0, {"level": "high", "text": "This address is on a list of known phishing sites."})
        elif safe_browsing_hit(url):
            score = 1.0
            reasons.insert(0, {"level": "high", "text": "Google Safe Browsing flags this address as dangerous."})
        elif (reg in TOP and reg not in SHARED_HOSTS and host in (reg, "www." + reg)
              and not any(r["level"] == "high" for r in reasons)):
            score = min(score, 0.35)
            reasons.append({"level": "good", "text": "A popular, long-established website (top 20,000 most visited)."})

    verdict = verdict_of(score)
    if not reasons and verdict == "legitimate":
        reasons.append({"level": "good", "text": "No common phishing patterns found in the address."})
    elif not reasons:
        reasons.append({"level": "low", "text": "No single red flag, but the overall pattern resembles known phishing addresses."})

    return jsonify(url=url, score=round(score * 100), verdict=verdict, reasons=reasons,
                   assumed_https=assumed_https, parts=url_parts(url, bool(f["has_ip_host"])))


@app.get("/api/game")
def game_new():
    """Eight fresh random links (4 phishing, 4 legit) from the data you collected."""
    def ok(u):
        return 12 <= len(u) <= 80 and u.isascii() and u.startswith(("http://", "https://")) and " " not in u
    bad = [u for u in PHISH_URLS if ok(u)]
    good = [u for u in LEGIT_URLS if ok(u)]
    if len(bad) < 4 or len(good) < 4:
        return jsonify(error="Not enough collected links yet."), 404
    items = [{"url": u, "phishing": True} for u in random.sample(bad, 4)] + \
            [{"url": u, "phishing": False} for u in random.sample(good, 4)]
    random.shuffle(items)
    return jsonify(items=items)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
