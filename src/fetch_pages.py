"""Stage 5a: fetch pages and save their content features.

Why this exists: URL text alone can't catch phishing pages on free hosting or
hacked normal sites. The page itself (password forms posting to another
domain, hidden iframes, etc.) can.

Safety design:
  * Plain HTTP GET only. No JavaScript is executed, nothing is rendered.
  * The HTML is parsed and thrown away; only numbers are saved.
  * Downloads are capped at 1 MB and only HTML/text is read.
  * Redirects are followed by hand (max 5) and private/local addresses are
    refused, so a URL can't point the script at your own network.

IMPORTANT - timing: phishing pages die within hours or days. Run this right
after you download the phishing feed, not a week later.

Examples (from the project folder):
    python src/collect_data.py --skip-legit          # refresh the phishing list
    python src/fetch_pages.py --source phishing      # fetch those pages now
    python src/fetch_pages.py --source legit --limit 1500

Results are appended to data/processed/page_features.csv. URLs already in
that file are skipped, so you can run it every day and the file keeps growing.
"""
import argparse
import csv
import ipaddress
import random
import socket
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

from build_dataset import load_legit, load_phishing
from page_features import PAGE_FEATURE_NAMES, extract_page_features, registered_domain

OUT = Path("data/processed/page_features.csv")
HEADERS = {"User-Agent": "Mozilla/5.0 (student phishing-detection research project)"}
META_COLUMNS = ["url", "fetch_ok", "status_code", "num_redirects", "final_domain_differs", "error"]
COLUMNS = META_COLUMNS + PAGE_FEATURE_NAMES


def _check_public(host):
    for info in socket.getaddrinfo(host, None):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ValueError("refusing private/local address")


def safe_get(url, allow_private=False, timeout=8, max_redirects=5, max_bytes=1_000_000):
    """Return (final_url, status_code, redirects, html_text). Raises on any problem."""
    current, redirects = url, 0
    for _ in range(max_redirects + 1):
        p = urlparse(current)
        if p.scheme not in ("http", "https") or not p.hostname:
            raise ValueError("bad scheme or host")
        if not allow_private:
            _check_public(p.hostname)
        r = requests.get(current, headers=HEADERS, timeout=timeout, allow_redirects=False, stream=True)
        if r.status_code in (301, 302, 303, 307, 308):
            location = r.headers.get("Location")
            r.close()
            if not location:
                raise ValueError("redirect without location")
            current, redirects = urljoin(current, location), redirects + 1
            continue
        ctype = r.headers.get("Content-Type", "").lower()
        if ctype and "html" not in ctype and "text" not in ctype:
            r.close()
            raise ValueError("not html")
        body = b""
        for chunk in r.iter_content(65536):
            body += chunk
            if len(body) >= max_bytes:
                break
        r.close()
        return current, r.status_code, redirects, body.decode(r.encoding or "utf-8", errors="ignore")
    raise ValueError("too many redirects")


def process_url(url, allow_private=False):
    try:
        final_url, status, redirects, html = safe_get(url, allow_private)
        row = {
            "url": url, "fetch_ok": 1, "status_code": status, "num_redirects": redirects,
            "final_domain_differs": int(registered_domain(final_url) != registered_domain(url)),
            "error": "",
        }
        row.update(extract_page_features(html, final_url))
        return row
    except Exception as exc:  # dead site, timeout, bad certificate, not HTML...
        return {"url": url, "fetch_ok": 0, "error": type(exc).__name__ + ": " + str(exc)[:80]}


def already_fetched():
    if not OUT.exists():
        return set()
    with OUT.open(encoding="utf-8", newline="") as f:
        return {row["url"] for row in csv.DictReader(f)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", choices=["phishing", "legit"], required=True)
    ap.add_argument("--limit", type=int, default=500, help="max NEW urls to fetch this run")
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--allow-private", action="store_true", help=argparse.SUPPRESS)  # for local testing
    args = ap.parse_args()

    urls = sorted(set(load_phishing() if args.source == "phishing" else load_legit()))
    done = already_fetched()
    todo = [u for u in urls if u not in done]
    random.Random(args.seed).shuffle(todo)
    todo = todo[: args.limit]
    print(f"{len(urls)} {args.source} URLs known, {len(done)} pages already fetched, fetching {len(todo)} now...")
    if not todo:
        return

    OUT.parent.mkdir(parents=True, exist_ok=True)
    new_file = not OUT.exists()
    ok = 0
    with OUT.open("a", encoding="utf-8", newline="") as f, ThreadPoolExecutor(args.workers) as pool:
        writer = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
        if new_file:
            writer.writeheader()
        for i, row in enumerate(pool.map(lambda u: process_url(u, args.allow_private), todo), 1):
            writer.writerow(row)
            ok += row["fetch_ok"]
            if i % 100 == 0:
                f.flush()
                print(f"  {i}/{len(todo)} done, {ok} fetched successfully")
    print(f"Finished: {ok}/{len(todo)} pages fetched OK (the rest were dead, blocked or not HTML).")
    print(f"Saved to {OUT}")


if __name__ == "__main__":
    main()
