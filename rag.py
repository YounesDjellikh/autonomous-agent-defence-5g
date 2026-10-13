"""RAG signature store: ChromaDB of labelled telemetry signatures, embedded via
Ollama nomic-embed-text. The agent retrieves the k nearest known signatures for
a query window and uses them as evidence."""
from __future__ import annotations
import chromadb
from chromadb.api.types import EmbeddingFunction, Documents, Embeddings
import ollama

import config
from schema import TelemetryWindow


class OllamaEmbed(EmbeddingFunction):
    """Embed documents with a local Ollama embedding model."""
    def __init__(self, model: str = config.EMBED_MODEL, base_url: str = config.OLLAMA_BASE_URL):
        self._client = ollama.Client(host=base_url)
        self._model = model

    def __call__(self, input: Documents) -> Embeddings:
        out = []
        for text in input:
            r = self._client.embeddings(model=self._model, prompt=text)
            out.append(r["embedding"])
        return out


def _client():
    config.CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(path=str(config.CHROMA_DIR))


def build_store(rows: list[dict], dedup: bool = True) -> int:
    """(Re)build the signature collection from labelled training rows.
    Each row is a dataset.csv record (dict) including its ground-truth 'label'.
    dedup=True collapses windows with an identical (describe-text, label) so the
    corpus stores distinct exemplars, not 39 copies of the same benign string."""
    client = _client()
    try:
        client.delete_collection(config.COLLECTION)
    except Exception:
        pass
    col = client.create_collection(config.COLLECTION, embedding_function=OllamaEmbed(),
                                   metadata={"hnsw:space": "cosine"})
    docs, metas, ids = [], [], []
    seen = set()
    for i, r in enumerate(rows):
        w = TelemetryWindow(**{k: r[k] for k in TelemetryWindow.model_fields if k in r})
        text = w.describe()
        key = (text, r["label"])
        if dedup and key in seen:
            continue
        seen.add(key)
        docs.append(text)
        metas.append({"label": r["label"], "plane": w.plane, "slice": w.slice,
                      "pps": float(w.pps), "cp_reg_rate": float(w.cp_reg_rate),
                      "scenario": r.get("scenario", "")})
        ids.append(f"sig-{len(ids)}")
    B = 64
    for s in range(0, len(docs), B):
        col.add(documents=docs[s:s+B], metadatas=metas[s:s+B], ids=ids[s:s+B])
    return col.count()


class SignatureStore:
    """Query wrapper over the persisted collection."""
    def __init__(self):
        self.col = _client().get_collection(config.COLLECTION, embedding_function=OllamaEmbed())

    def retrieve(self, window: TelemetryWindow, k: int = config.K_RETRIEVE,
                 plane_filter: bool = True) -> list[dict]:
        where = {"plane": window.plane} if plane_filter else None
        res = self.col.query(query_texts=[window.describe()], n_results=k, where=where,
                             include=["documents", "metadatas", "distances"])
        hits = []
        for doc, meta, dist in zip(res["documents"][0], res["metadatas"][0], res["distances"][0]):
            hits.append({"text": doc, "label": meta["label"],
                         "similarity": round(1 - dist, 3), **meta})
        return hits

    def knn_predict(self, window: TelemetryWindow, k: int = config.K_RETRIEVE) -> tuple[str, float]:
        """Pure retrieval baseline: majority label of the k nearest signatures.
        If the agent can't beat this, the LLM is adding nothing."""
        hits = self.retrieve(window, k)
        if not hits:
            return "benign", 0.0
        from collections import Counter
        votes = Counter(h["label"] for h in hits)
        label, n = votes.most_common(1)[0]
        return label, round(n / len(hits), 3)

    def max_similarity(self, window: TelemetryWindow) -> float:
        """Leakage audit: similarity of a window's nearest corpus neighbour
        (≈1.0 means an identical twin is in the corpus)."""
        hits = self.retrieve(window, k=1, plane_filter=False)
        return hits[0]["similarity"] if hits else 0.0

    def count(self) -> int:
        return self.col.count()
