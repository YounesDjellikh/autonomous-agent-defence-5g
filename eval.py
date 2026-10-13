#!/usr/bin/env python3
"""Phase 3 evaluation harness — honest, multi-system comparison.

Compares, on the SAME held-out windows:
  rule        : threshold rule-based monitor (the dissertation baseline)
  knn         : majority label of k nearest RAG signatures (pure retrieval, no LLM)
  agent-full  : LLM + RAG (labels shown)
  agent-blind : LLM + RAG with neighbour labels HIDDEN (reason, don't copy)
  agent-norag : LLM with no retrieval (window only)

Guards against the leakage the review found:
  - GROUP split on describe()-key so identical windows never cross train/test
  - corpus de-duplicated
  - per-test-window leakage audit (nearest-neighbour similarity distribution)

Metrics: macro-F1, per-class P/R/F1, and false-block rate (benign windows
predicted as an attack => would be wrongly blocked) — the metric the claim is about.

  python eval.py                       # rule + knn on all; agents on all (slow)
  python eval.py --limit 24            # cap agent calls for a quick pass
  python eval.py --agents full         # only the full agent (skip ablations)
  python eval.py --train other.csv --test held.csv   # independent-capture protocol (3b)
"""
import sys, argparse, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import f1_score, precision_recall_fscore_support

import config
from schema import TelemetryWindow
import rag
from agent import IdsAgent
from baseline import RuleBasedMonitor

LABELS = config.LABELS


def to_window(r: dict) -> TelemetryWindow:
    return TelemetryWindow(**{k: r[k] for k in TelemetryWindow.model_fields if k in r})


def describe_key(r: dict) -> str:
    return to_window(r).describe()


def metrics(y_true, y_pred):
    macro = f1_score(y_true, y_pred, labels=LABELS, average="macro", zero_division=0)
    p, r, f, _ = precision_recall_fscore_support(y_true, y_pred, labels=LABELS, zero_division=0)
    # false-block: a benign window predicted as an attack (would be wrongly contained)
    benign_total = sum(t == "benign" for t in y_true)
    false_blocks = sum(t == "benign" and ppred != "benign" for t, ppred in zip(y_true, y_pred))
    fbr = false_blocks / benign_total if benign_total else 0.0
    # missed attacks: attack window predicted benign
    atk_total = sum(t != "benign" for t in y_true)
    missed = sum(t != "benign" and pp == "benign" for t, pp in zip(y_true, y_pred))
    miss_rate = missed / atk_total if atk_total else 0.0
    return {"macro_f1": macro, "false_block_rate": fbr, "miss_rate": miss_rate,
            "per_class": {lab: {"P": round(p[i], 2), "R": round(r[i], 2), "F1": round(f[i], 2)}
                          for i, lab in enumerate(LABELS)}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=str(config.DATASET))
    ap.add_argument("--train", default="")     # independent-capture protocol (3b)
    ap.add_argument("--test", default="")
    ap.add_argument("--split", type=float, default=0.35)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--agents", default="full,blind,norag", help="comma: full,blind,norag (or 'none')")
    ap.add_argument("--train-scenarios", default="", help="restrict CORPUS to these scenarios (novel-attack test)")
    ap.add_argument("--test-scenarios", default="", help="restrict TEST to these scenarios")
    ap.add_argument("--out", default=str(config.REPO / "data" / "eval_results.csv"))
    a = ap.parse_args()

    # ---- assemble train (corpus) + test ----
    if a.train and a.test:
        train = pd.read_csv(a.train); test = pd.read_csv(a.test)
        print(f"independent captures: train={len(train)} test={len(test)}")
    else:
        df = pd.read_csv(a.dataset)
        groups = df.apply(lambda r: describe_key(r.to_dict()), axis=1)   # identical windows = one group
        gss = GroupShuffleSplit(n_splits=1, test_size=a.split, random_state=a.seed)
        tr_idx, te_idx = next(gss.split(df, groups=groups))
        train, test = df.iloc[tr_idx], df.iloc[te_idx]
        print(f"GROUP split (no describe-twin crosses): train={len(train)} test={len(test)}")
        ng = len(set(groups)); print(f"distinct window-signatures (groups): {ng} of {len(df)} rows")

    if a.train_scenarios:
        keep = set(a.train_scenarios.split(","))
        train = train[train["scenario"].isin(keep)]
        print(f"CORPUS restricted to {sorted(keep)} -> {len(train)} rows "
              f"(NOVEL-ATTACK test: corpus has no signatures for the held-out attacks)")
    if a.test_scenarios:
        keep = set(a.test_scenarios.split(","))
        test = test[test["scenario"].isin(keep)]
        print(f"TEST restricted to {sorted(keep)} -> {len(test)} rows")

    n_corpus = rag.build_store(train.to_dict("records"), dedup=True)
    print(f"RAG corpus: {n_corpus} de-duplicated signatures")

    rows = test.to_dict("records")
    if a.limit:
        # cover every scenario (esp. the ambiguous ones), attack rows first
        dfr = pd.DataFrame(rows)
        n_scen = max(1, dfr["scenario"].nunique())
        per = max(2, a.limit // n_scen)
        dfr["_atk"] = (dfr["label"] != "benign").astype(int)
        rows = (dfr.sort_values(["scenario", "_atk"], ascending=[True, False])
                   .groupby("scenario", group_keys=False).head(per)
                   .drop(columns="_atk").to_dict("records"))
        print(f"limited to {len(rows)} windows ({per}/scenario, attack rows first)")

    y_true = [r["label"] for r in rows]
    windows = [to_window(r) for r in rows]

    # ---- instant baselines (no LLM): rule + leakage audit + kNN ----
    rule = RuleBasedMonitor()
    store = rag.SignatureStore()
    preds = {"rule": [rule.classify(w).label for w in windows],
             "knn":  [store.knn_predict(w)[0] for w in windows]}
    sims = [store.max_similarity(w) for w in windows]

    # ---- agent variants (LLM; the slow part) ----
    want = [] if a.agents == "none" else a.agents.split(",")
    cfg = {"full": dict(use_rag=True, blind_labels=False),
           "blind": dict(use_rag=True, blind_labels=True),
           "norag": dict(use_rag=False, blind_labels=False)}
    for name in want:
        agent = IdsAgent(audit=(name == "full"), **cfg[name])
        t0 = time.time(); out = []
        for i, w in enumerate(windows, 1):
            v, _ = agent.classify(w)
            out.append(v.label)
            print(f"  agent-{name} [{i}/{len(windows)}] true={y_true[i-1]:<7} pred={v.label}")
        preds[f"agent-{name}"] = out
        print(f"  agent-{name}: {time.time()-t0:.0f}s")

    # ---- leakage audit ----
    sims = np.array(sims)
    print("\n" + "=" * 64)
    print("LEAKAGE AUDIT (nearest-neighbour similarity of each test window):")
    print(f"  mean {sims.mean():.3f}  median {np.median(sims):.3f}  "
          f">0.99: {(sims>0.99).sum()}/{len(sims)}  >0.95: {(sims>0.95).sum()}/{len(sims)}")
    print("  (many ~1.0 => identical twins remain in corpus => results inflated)")

    # ---- scoreboard ----
    print("\nSCOREBOARD (held-out, n={}):".format(len(y_true)))
    hdr = f"  {'system':<12} {'macroF1':>8} {'false_block':>12} {'miss_rate':>10}   per-class F1 (benign/flood/attach)"
    print(hdr)
    summary = []
    for name, yp in preds.items():
        m = metrics(y_true, yp)
        pc = m["per_class"]
        print(f"  {name:<12} {m['macro_f1']:>8.2f} {m['false_block_rate']:>12.2f} "
              f"{m['miss_rate']:>10.2f}   {pc['benign']['F1']}/{pc['flood']['F1']}/{pc['attach']['F1']}")
        summary.append({"system": name, **{k: v for k, v in m.items() if k != "per_class"},
                        **{f"{c}_F1": pc[c]["F1"] for c in LABELS}})

    pd.DataFrame([{**r, **{f"pred_{k}": preds[k][i] for k in preds}, "nn_sim": float(sims[i])}
                  for i, r in enumerate(rows)]).to_csv(a.out, index=False)
    pd.DataFrame(summary).to_csv(a.out.replace(".csv", "_summary.csv"), index=False)
    print(f"\nper-window -> {a.out}")
    print(f"summary    -> {a.out.replace('.csv','_summary.csv')}")


if __name__ == "__main__":
    main()
