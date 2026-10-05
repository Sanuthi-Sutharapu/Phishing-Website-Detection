"""Stage 4: train several models and evaluate them honestly.

Key idea: the train/test split is done by DOMAIN, so links from the same site
(or URLs from the same phishing campaign) never appear on both sides. A plain
random split leaks near-duplicates and makes accuracy look better than it is.
The script also prints the random-split score so you can see the difference.

Run from the project folder:
    python src/train.py
Outputs:
    models/model.joblib              best model (by PR-AUC) + feature list
    models/metrics.json              scores of all models
    models/feature_importance.png    which features mattered most
"""
import argparse
import json
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.base import clone
from sklearn.ensemble import (
    GradientBoostingClassifier,
    HistGradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_sample_weight

from features import FEATURE_NAMES, _split_host

DATA = Path("data/processed/dataset.csv")
MODELS = Path("models")


def registered_domain(host):
    host = str(host)
    return _split_host(host)[1] or host


def make_models(seed):
    # (estimator, needs_sample_weight)
    return {
        "LogisticRegression": (
            make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced")),
            False,
        ),
        "RandomForest": (
            RandomForestClassifier(n_estimators=300, class_weight="balanced_subsample",
                                   n_jobs=-1, random_state=seed),
            False,
        ),
        "GradientBoosting": (GradientBoostingClassifier(random_state=seed), True),
        "HistGradientBoosting": (
            HistGradientBoostingClassifier(class_weight="balanced", random_state=seed),
            False,
        ),
    }


def fit(model, needs_weight, X, y):
    if needs_weight:
        model.fit(X, y, sample_weight=compute_sample_weight("balanced", y))
    else:
        model.fit(X, y)
    return model


def evaluate(y_true, proba, threshold=0.5):
    pred = (proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    return {
        "precision": precision_score(y_true, pred, zero_division=0),
        "recall": recall_score(y_true, pred),
        "f1": f1_score(y_true, pred),
        "roc_auc": roc_auc_score(y_true, proba),
        "pr_auc": average_precision_score(y_true, proba),
        "false_positive_rate": fp / max(fp + tn, 1),
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }


def grouped_split(df, groups, test_size, seed):
    for offset in range(50):
        gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed + offset)
        tr, te = next(gss.split(df, df["label"], groups))
        if df["label"].iloc[tr].nunique() == 2 and df["label"].iloc[te].nunique() == 2:
            return tr, te
    raise SystemExit("Could not make a split containing both classes. Collect more data.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    df = pd.read_csv(DATA).reset_index(drop=True)
    print(f"Loaded {len(df)} rows | phishing: {int(df['label'].sum())} | legit: {int((df['label'] == 0).sum())}")
    X, y = df[FEATURE_NAMES], df["label"]
    groups = df["host"].map(registered_domain)

    tr, te = grouped_split(df, groups, args.test_size, args.seed)
    X_tr, X_te, y_tr, y_te = X.iloc[tr], X.iloc[te], y.iloc[tr], y.iloc[te]
    print(f"Train: {len(tr)} rows ({groups.iloc[tr].nunique()} domains) | "
          f"Test: {len(te)} rows ({groups.iloc[te].nunique()} domains) - no domain appears in both\n")

    results, fitted = {}, {}
    for name, (model, needs_w) in make_models(args.seed).items():
        print(f"Training {name}...")
        fitted[name] = fit(model, needs_w, X_tr, y_tr)
        results[name] = evaluate(y_te, fitted[name].predict_proba(X_te)[:, 1])

    table = pd.DataFrame(results).T
    for c in ["tp", "fp", "tn", "fn"]:
        table[c] = table[c].astype(int)
    show = ["precision", "recall", "f1", "roc_auc", "pr_auc", "false_positive_rate", "tp", "fp", "tn", "fn"]
    print("\n=== Results on domain-held-out test set ===")
    print(table[show].round(3).to_string())

    best = max(results, key=lambda k: results[k]["pr_auc"])
    print(f"\nBest by PR-AUC: {best}")

    # Compare with a naive random split to show how much leakage inflates scores.
    Xr_tr, Xr_te, yr_tr, yr_te = train_test_split(X, y, test_size=args.test_size,
                                                  stratify=y, random_state=args.seed)
    est, needs_w = make_models(args.seed)[best]
    est = fit(clone(est), needs_w, Xr_tr, yr_tr)
    rnd = evaluate(yr_te, est.predict_proba(Xr_te)[:, 1])
    print(f"Same model with a naive RANDOM split: PR-AUC {rnd['pr_auc']:.3f}, recall {rnd['recall']:.3f} "
          f"(vs {results[best]['pr_auc']:.3f} / {results[best]['recall']:.3f} domain-held-out). "
          "A big gap means the random split was flattering the model.")

    MODELS.mkdir(exist_ok=True)
    joblib.dump({"model": fitted[best], "features": FEATURE_NAMES, "threshold": 0.5,
                 "name": best, "metrics": results[best]}, MODELS / "model.joblib")
    (MODELS / "metrics.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

    imp = permutation_importance(fitted[best], X_te, y_te, scoring="average_precision",
                                 n_repeats=5, random_state=args.seed)
    top = pd.Series(imp.importances_mean, index=FEATURE_NAMES).sort_values().tail(15)
    plt.figure(figsize=(8, 6))
    top.plot.barh()
    plt.xlabel("Drop in PR-AUC when the feature is shuffled")
    plt.title(f"Top features ({best})")
    plt.tight_layout()
    plt.savefig(MODELS / "feature_importance.png", dpi=120)
    print(f"\nSaved models/model.joblib, models/metrics.json, models/feature_importance.png")


if __name__ == "__main__":
    main()
