"""Stage 2: collect raw URLs.

  * Phishing URLs -> downloaded as a plain LIST from OpenPhish. This script
    NEVER visits those URLs, it only saves the text of the feed.
  * Legitimate URLs -> Tranco top-sites list, then we visit those (safe,
    popular) sites and collect a few real internal links from each, so that
    legitimate examples have realistic paths and not just bare domains.

Usage (from the project folder):
    python src/collect_data.py --n-sites 3000

If a download fails (network blocked, feed changed), download the files
manually into data/raw/ - see README.md.
"""
import argparse
import io
import random
import zipfile
from datetime import date
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

RAW = Path("data/raw")
OPENPHISH_URL = "https://openphish.com/feed.txt"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
HEADERS = {"User-Agent": "Mozilla/5.0 (student phishing-detection research project)"}


def download_openphish():
    print("Downloading OpenPhish feed (list of URLs only)...")
    r = requests.get(OPENPHISH_URL, headers=HEADERS, timeout=30)
    r.raise_for_status()
    out = RAW / f"openphish_{date.today()}.txt"  # one file per day, they accumulate
    out.write_text(r.text, encoding="utf-8")
    print(f"  saved {len(r.text.splitlines())} phishing URLs -> {out}")


def download_tranco(top_n):
    print("Downloading Tranco top-sites list...")
    r = requests.get(TRANCO_URL, headers=HEADERS, timeout=120)
    r.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        name = z.namelist()[0]
        lines = z.read(name).decode("utf-8").splitlines()[:top_n]
    out = RAW / "tranco_top.csv"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"  saved top {len(lines)} domains -> {out}")


def _crawl_one(domain, max_links):
    """Fetch a homepage and return up to max_links same-site URLs."""
    found = set()
    base = f"https://{domain}/"
    try:
        resp = requests.get(base, headers=HEADERS, timeout=6)
        if "text/html" not in resp.headers.get("Content-Type", ""):
            return [base]
        found.add(resp.url)
        soup = BeautifulSoup(resp.text, "html.parser")
        for a in soup.find_all("a", href=True):
            link = urljoin(resp.url, a["href"]).split("#")[0]
            p = urlparse(link)
            if p.scheme in ("http", "https") and p.hostname and p.hostname.endswith(domain):
                found.add(link)
            if len(found) > max_links:
                break
    except Exception:
        return []
    return list(found)[: max_links + 1]


def collect_legit(n_sites, max_links, seed=42):
    lines = (RAW / "tranco_top.csv").read_text(encoding="utf-8").splitlines()
    domains = [ln.split(",")[1] for ln in lines if "," in ln]
    random.Random(seed).shuffle(domains)
    domains = domains[:n_sites]
    print(f"Visiting {len(domains)} popular sites to collect real links (a few minutes)...")
    urls = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        for i, result in enumerate(pool.map(lambda d: _crawl_one(d, max_links), domains), 1):
            urls.extend(result)
            if i % 500 == 0:
                print(f"  {i}/{len(domains)} sites done, {len(urls)} URLs so far")
    urls = sorted(set(urls))
    out = RAW / "legit_urls.txt"
    out.write_text("\n".join(urls), encoding="utf-8")
    print(f"  saved {len(urls)} legitimate URLs -> {out}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-sites", type=int, default=3000, help="legit sites to crawl")
    ap.add_argument("--max-links", type=int, default=5, help="links kept per site")
    ap.add_argument("--top-n", type=int, default=50000, help="use top N Tranco domains")
    ap.add_argument("--skip-phishing", action="store_true")
    ap.add_argument("--skip-legit", action="store_true")
    args = ap.parse_args()

    RAW.mkdir(parents=True, exist_ok=True)
    if not args.skip_phishing:
        download_openphish()
    if not args.skip_legit:
        download_tranco(args.top_n)
        collect_legit(args.n_sites, args.max_links)
    print("Done. Next: python src/build_dataset.py")
