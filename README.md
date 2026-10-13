# Autonomous Agent Defence for 5G Network Slices

An LLM-based intrusion detection agent that reasons over network flow telemetry on a virtualised 5G core, evaluated against an autonomous adversarial red team.

MSc Cyber Security dissertation, London South Bank University, 2026. Mark: 68.

---

## Summary

Rule-based and signature-based intrusion detection struggles against coordinated, distributed attackers: each individual source looks benign, and only the pattern across sources reveals the attack. Classical machine learning approaches can catch some of this, but need retraining to adapt to new behaviour.

This project asked whether a retrieval-augmented language model agent could do better — reasoning over flow-level features in context, and adapting to new attacker behaviour by **growing its retrieval corpus rather than retraining the model**.

The short answer is yes, under the conditions tested, and the project's main contribution is the adversarial evaluation that establishes how far that holds.

---

## Results

### Detection against coordinated distributed attackers

| Method | Recall |
|---|---|
| Per-source rule baseline | 0 / 6 |
| Aggregate rule baseline | 0 / 6 |
| k-NN retrieval baseline | 3 / 6 |
| **RAG LLM agent (Qwen3-8B)** | **5 / 6** |

The rule baselines fail completely because no single source crosses a threshold. The k-NN baseline catches half. The agent, reasoning over the retrieved context rather than matching against it, catches five of six.

### Adaptation under adversarial pressure

An autonomous LLM red team was given the task of evading detection, over ten rounds. Between rounds, confirmed detections were added to the retrieval corpus — **no model weights were changed at any point**.

| | Window-level evasion rate |
|---|---|
| Round 1 | 68% |
| Round 10 | **24%** |

Evasion fell by roughly two thirds through retrieval-corpus growth alone. This is the result the project is really about: a detection methodology that adapts through data rather than retraining.

---

## Architecture

```
UERANSIM (simulated UEs / gNB)
        │
        ▼
   Open5GS 5G core  ──────►  NetFlow capture
        │                          │
        │                          ▼
        │                 Per-window feature extraction
        │                          │
        │                          ▼
        │                  ChromaDB retrieval
        │                          │
        │                          ▼
        │              Qwen3-8B reasoning agent
        │                          │
        │                    structured verdict
        │                          ▼
        └──────────────  Safety-envelope controller
```

The agent emits a structured verdict rather than free text, which the safety-envelope controller consumes. The envelope exists so that the model cannot take an action outside a bounded set — an LLM in the control path of a network is only acceptable if its authority is explicitly constrained.

---

## Validation

A single good number proves very little, so most of the project was spent trying to break the result.

**Six-step falsification chain.** Each step was designed to produce the finding by some mechanism other than the one claimed — leakage, ordering effects, trivially separable features, and so on. The result survived all six.

**External corpus.** Validated against **5G-NIDD**, a public dataset the system was never developed against, to test whether the finding was an artefact of the local testbed.

**Architecture replication.** The full pipeline was re-run across three model families — **Qwen3**, **Llama-3.1-8B** and **Mistral-7B** — to test whether the result depended on one specific model. It did not.

---

## Stack

**Network:** Open5GS, UERANSIM, VirtualBox, NetFlow, Wireshark, tcpdump
**ML / LLM:** Qwen3 (4B–32B), Llama-3.1-8B, Mistral-7B, vLLM, Ollama, LangChain, ChromaDB
**Data:** Python, pandas
**Infrastructure:** Ubuntu Linux, GPU / CUDA, Bash

Everything ran on consumer GPU hardware. No cloud inference was used at any point, which was a deliberate constraint — security telemetry should not have to leave the network to be analysed.

---

## Limitations

Stated plainly, because a result without its boundaries is not a result.

- **Scale.** A virtualised testbed is not a production 5G core. Traffic volumes, tenant diversity and failure modes all differ.
- **Latency.** LLM inference is orders of magnitude slower than rule evaluation. This is viable for windowed analysis, not for line-rate inline blocking.
- **Red team ceiling.** The adversary was itself an LLM. A skilled human attacker with knowledge of the detection method would likely perform better.
- **Corpus growth.** Retrieval-corpus growth improves detection but grows unbounded. Pruning strategy was not addressed and is the obvious next piece of work.
- **One failure persisted.** The sixth attack was never caught. That case is characterised in the dissertation rather than explained away.

---

## Repository structure

```
/testbed      Open5GS and UERANSIM configuration, VM bring-up scripts
/capture      NetFlow capture and per-window feature extraction
/agent        Retrieval pipeline, prompt construction, verdict schema
/baselines    Per-source rule, aggregate rule, k-NN implementations
/redteam      Adversarial loop and round-by-round evasion measurement
/eval         Falsification chain, 5G-NIDD validation, replication runs
/results      Figures and result tables
```

---

## Author

**Younes Zineddine Djellikh**
MSc Cyber Security, London South Bank University
Supervisor: Dr Brahim El Boudani

[LinkedIn](https://www.linkedin.com/in/younes-zineddine-djellikh-898397232)

Happy to discuss the methodology, the failure modes, or the parts that did not work.
