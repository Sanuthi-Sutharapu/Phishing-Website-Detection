"""Stage 3: turn raw URL lists into a labeled feature table.

Reads:
    data/raw/openphish*.txt      one phishing URL per line
    data/raw/phishtank*.csv      optional, needs a 'url' column
    data/raw/legit_urls.txt      one legitimate URL per line
Writes:
    data/processed/dataset.csv   url + host + label (1 = phishing) + features
"""
import argparse
import glob
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd

from features import extract_url_features

RAW = Path("data/raw")
OUT = Path("data/processed/dataset.csv")


def read_lines(path):
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def load_phishing():
    urls = []
    for p in glob.glob(str(RAW / "openphish*.txt")):
        urls += read_lines(p)
    for p in glob.glob(str(RAW / "phishtank*.csv")):
        urls += pd.read_csv(p)["url"].dropna().astype(str).tolist()
    return urls


def load_legit():
    p = RAW / "legit_urls.txt"
    return read_lines(p) if p.exists() else []


def host_of(url):
    try:
        return (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    except ValueError:
        return ""


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--balance", action="store_true", help="downsample to equal class sizes")
    args = ap.parse_args()

    phish = sorted(set(load_phishing()))
    legit = sorted(set(load_legit()) - set(phish))
    print(f"Unique phishing URLs: {len(phish)} | unique legitimate URLs: {len(legit)}")
    if not phish or not legit:
        raise SystemExit("Need both classes. Run src/collect_data.py first (or add files to data/raw/).")

    df = pd.DataFrame({"url": phish + legit, "label": [1] * len(phish) + [0] * len(legit)})
    if args.balance:
        k = df["label"].value_counts().min()
        df = df.groupby("label", group_keys=False).sample(n=k, random_state=42)
        print(f"Balanced to {k} per class")

    feats = pd.DataFrame([extract_url_features(u) for u in df["url"]])
    out = pd.concat([df.reset_index(drop=True), feats], axis=1)
    out.insert(1, "host", out["url"].map(host_of))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(OUT, index=False)
    print(f"Saved {len(out)} rows x {feats.shape[1]} features -> {OUT}")
