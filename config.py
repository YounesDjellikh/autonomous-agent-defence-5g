"""Central configuration for the agentic IDS."""
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]      # .../5g-agentic-ids

# --- LLM / embeddings (Ollama) ---
OLLAMA_BASE_URL = "http://10.0.2.2:11434"
AGENT_MODEL     = "qwen3:8b"          # tool-calling + reasoning; 4b is the fast fallback
EMBED_MODEL     = "nomic-embed-text"  # 768-dim RAG embeddings
LLM_TEMPERATURE = 0.0                 # deterministic verdicts for reproducibility
LLM_REASONING   = False               # qwen3 thinking off in the loop (RAG carries evidence); flip on to study effect

# --- RAG store ---
CHROMA_DIR   = REPO / "data" / "chroma_db"
COLLECTION   = "signatures_5g"
K_RETRIEVE   = 5                      # nearest known signatures per query

# --- data / artifacts ---
DATASET      = REPO / "data" / "dataset.csv"
AUDIT_DIR    = REPO / "data" / "audit"
AUDIT_LOG    = AUDIT_DIR / "decisions.jsonl"

# --- domain knowledge (kept here so prompt + corpus agree) ---
SLICES = {
    "iot":      "Industrial-IoT slice (SST 3, DNN iot) — the protected slice; steady low-rate sensor telemetry is normal.",
    "internet": "Public-Internet slice (SST 1, DNN internet) — bursty web/streaming traffic is normal.",
    "core":     "5G core control plane (AMF/SMF) — NAS signalling; near-zero registration rate is normal in steady state.",
}
ATTACK_TYPES = {
    "flood":  "Volumetric flooding: a UE blasts very high packet-rate traffic, saturating its slice (user plane).",
    "attach": "High-frequency attachment requests: a UE repeatedly registers, storming the AMF (control plane).",
}
LABELS = ["benign", "flood", "attach"]
