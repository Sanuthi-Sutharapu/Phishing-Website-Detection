"""Look closely at what the saved model gets wrong.

Shows:
  1. How precision / recall / false-positive-rate change with the threshold
  2. The threshold that keeps false positives at or below a target rate
  3. The most confident false positives (legit URLs flagged as phishing)
     and false negatives (phishing URLs the model missed)

Uses the same seed and split as train.py, so it looks at the same test set.
Run from the project folder, after train.py:
    python src/analyze.py

NOTE: the false-negative list contains real phishing URLs as plain text.
Read them, but never open them in a browser.
"""
import argparse

import joblib
import pandas as pd

from features import FEATURE_NAMES
from train import DATA, MODELS, evaluate, grouped_split, registered_domain

ap = argparse.ArgumentParser()
ap.add_argument("--seed", type=int, default=42)
ap.add_argument("--test-size", type=float, default=0.2)
ap.add_argument("--top", type=int, default=15)
ap.add_argument("--target-fpr", type=float, default=0.01)
args = ap.parse_args()

bundle = joblib.load(MODELS / "model.joblib")
df = pd.read_csv(DATA).reset_index(drop=True)
groups = df["host"].map(registered_domain)
_, te = grouped_split(df, groups, args.test_size, args.seed)
test = df.iloc[te].copy()
test["proba"] = bundle["model"].predict_proba(test[FEATURE_NAMES])[:, 1]
y = test["label"]
print(f"Model: {bundle['name']} | test rows: {len(test)} "
      f"(phishing: {int(y.sum())}, legit: {int((y == 0).sum())})\n")

# 1. Threshold table
rows = []
for thr in [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95]:
    m = evaluate(y, test["proba"], thr)
    rows.append({"threshold": thr, "precision": m["precision"], "recall": m["recall"],
                 "false_positive_rate": m["false_positive_rate"], "fp": m["fp"], "fn": m["fn"]})
print("=== Effect of the decision threshold ===")
print(pd.DataFrame(rows).round(3).to_string(index=False))

# 2. Best recall under a false-positive budget
best = None
for i in range(1, 100):
    thr = i / 100
    m = evaluate(y, test["proba"], thr)
    if m["false_positive_rate"] <= args.target_fpr and (best is None or m["recall"] > best[1]["recall"]):
        best = (thr, m)
print(f"\n=== Best recall with false positive rate <= {args.target_fpr:.1%} ===")
if best:
    thr, m = best
    print(f"threshold {thr:.2f} -> recall {m['recall']:.3f}, precision {m['precision']:.3f}, "
          f"false positives {m['fp']}, missed phishing {m['fn']}")
else:
    print("No threshold reaches that false-positive rate on this test set.")

# 3. Worst mistakes
pd.set_option("display.max_colwidth", 110)
pd.set_option("display.width", 200)
fp = test[y == 0].sort_values("proba", ascending=False).head(args.top)
fn = test[y == 1].sort_values("proba", ascending=True).head(args.top)
print(f"\n=== Legit URLs with the HIGHEST phishing scores (top {args.top}; above 0.5 = false positive) ===")
print(fp[["proba", "url"]].round(3).to_string(index=False))
print(f"\n=== Phishing URLs with the LOWEST scores (top {args.top}; below 0.5 = missed) ===")
print(fn[["proba", "url"]].round(3).to_string(index=False))

errors = test[((y == 0) & (test["proba"] >= 0.5)) | ((y == 1) & (test["proba"] < 0.5))]
out = MODELS / "errors.csv"
errors[["label", "proba", "url"]].sort_values("proba").to_csv(out, index=False)
print(f"\nAll {len(errors)} mistakes at threshold 0.5 saved to {out}")
