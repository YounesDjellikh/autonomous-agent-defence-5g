# Autonomous Agent Defence for 5G Network Slices

An LLM-based intrusion detection and containment agent for a virtualised 5G core, benchmarked against rule-based and retrieval baselines through an identical evaluation harness.

MSc Cyber Security dissertation, London South Bank University, 2026. Dissertation mark: 68.

---

## Summary

Rule-based intrusion detection on a 5G core is brittle: a fixed threshold has no notion of graded certainty, and misses attacks that don't cross it. This project tests whether a retrieval-augmented LLM agent, reasoning over per-window network telemetry, can do better — and, crucially, whether that claim survives honest evaluation rather than a single lucky run.

The agent reaches a perfect classification score on the test set with zero variance across repeats, and **Pareto-dominates** the rule baseline: same false-block cost, strictly higher detection. The project's real contribution is the evaluation discipline around that result — repeated runs for variance, a controllability trade-off curve, and an explicit account of what the data does *not* yet prove.

---

## Results

### Experiment 1 — Classification, with variance (n = 21 windows × 5 repeats = 105 calls)

| System | macro-F1 | False-block rate | Miss rate |
|---|---|---|---|
| Rule | 0.57 | 0.00 | 0.27 |
| k-NN (retrieval) | 1.00 | 0.00 | 0.00 |
| **Agent (Qwen3-8B)** | **1.00 ± 0.00** | **0.00 ± 0.00** | **0.00 ± 0.00** |

The agent's confusion matrix is a perfect diagonal across all 105 pooled windows — 30/30 benign, 60/60 flood, 15/15 attach, zero misclassifications.

**On variance:** the Phase 3 methodology review flagged that an LLM at temperature 0 is not guaranteed to be deterministic. Across five independent repeats, the agent's macro-F1 was exactly 1.00 every time (std = 0.00). That is an empirical finding about *this* model in *this* environment (Ollama, Qwen3-8B, temperature 0), not a general claim about LLM determinism.

### Experiment 2 — Effectiveness vs. controllability

The rule emits confidence 1.0 always, so it is a single fixed operating point: **73% effectiveness at 0% false-block rate**. The agent, having graded confidence, traces a curve — and sits at **100% effectiveness / 0% false-block** across almost the entire confidence-threshold range.

**Finding — Pareto dominance.** The agent's operating region strictly dominates the rule's point: same false-block cost (0%), strictly higher effectiveness (100% vs 73%). There is no threshold on this data at which the rule is preferable.

### Experiment 3 — Live containment (MTTD / MTTC)

A full live run demonstrated the end-to-end mechanism: agent detects a flood (confidence 0.997) → controller blocks **only** the attacker UE under human-on-the-loop approval → the attacker is contained while other UEs on the same and other slices stay up → kill switch flushes every rule. **MTTD ≈ MTTC ≈ 26.6s**, dominated by inference and approval latency rather than network propagation.

---

## Architecture

```
UERANSIM (simulated UEs / gNB)
        │
        ▼
   Open5GS 5G core  ──────►  per-window telemetry capture (tshark)
        │                          │
        │                          ▼
        │                 feature extraction
        │                          │
        │                          ▼
        │                 ChromaDB retrieval (k=5)
        │                          │
        │                          ▼
        │             Qwen3-8B reasoning agent  ──► structured verdict
        │                          │
        └────────  mitigation controller (human-on-the-loop)
                                   │
                          block attacker UE only · kill switch
```

The agent emits a structured verdict (see `schema.py`) rather than free text, and the controller acts under human approval with a kill switch — an LLM in the control path of a network is only acceptable if its authority is explicitly bounded.

---

## Honest limitations

Recorded plainly, because a result without its boundaries is not a result.

- **The trade-off curve is degenerate.** It is flat at the ideal corner because the agent was uniformly confident *and* correct on this sample, so the confidence threshold isn't doing discriminating work. A genuinely sloped effectiveness/false-block frontier needs test cases engineered to sit near the agent's decision boundary — scoped as future work, not papered over.
- **No repeated-run MTTD/MTTC statistic.** Automating N live runs surfaced a real testbed limitation: UE PDU sessions in the VirtualBox VM (software CPU emulation) drop within seconds under repeated flood stress. This was root-caused through a chain of diagnostics, two fixes were committed, and it still wouldn't hold a session long enough for a clean sample. Experiments 1–2 are unaffected — they run on previously-captured static telemetry. The single live run stands as qualitative proof of mechanism.
- **Modest sample size (n = 21 × 5).** Deliberately bounded by real-time LLM inference cost (~35s/window through NAT and software emulation). Adequate for the claims made; explicitly not a large-scale benchmark.
- **Virtualised, not production.** A VirtualBox 5G core is not a live network. Traffic volumes, tenant diversity and failure modes all differ.

---

## Stack

**Network:** Open5GS, UERANSIM, VirtualBox, tshark
**LLM / retrieval:** Qwen3-8B (Ollama), nomic-embed-text, ChromaDB, LangChain
**Data / eval:** Python, pandas, scikit-learn, matplotlib
**Infrastructure:** Ubuntu Linux, Bash

All inference ran locally on consumer hardware — security telemetry should not have to leave the network to be analysed.

---

## Repository structure

```
src_dump/          agent, retrieval, baselines, evaluation, verdict schema
phase5_out/         result figures and trade-off / curve CSVs
00-project-plan.md  project plan and phase structure
08-*.md, 09-*.md    migration notes and the Phase 5 evaluation writeup
```

---

## Author

**Younes Zineddine Djellikh**
MSc Cyber Security, London South Bank University
Supervisor: Dr Brahim El Boudani

[LinkedIn](https://www.linkedin.com/in/younes-zineddine-djellikh-898397232)

Happy to walk through the methodology, the live-run limitation, or the parts that didn't work.
