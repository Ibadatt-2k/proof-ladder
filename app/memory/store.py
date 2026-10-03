"""Corrections memory. An analyst fixes a verdict once; similar alerts retrieve it as precedent.

Embeddings are a signed feature-hashing of the alert's deterministic signature, so the
same pattern always lands in the same place and no embedding API is required. Swap in
a model embedding later without changing the interface.
"""
import hashlib

import numpy as np

from app.config import get_settings

DIM = 512


def embed(signature: str) -> np.ndarray:
    v = np.zeros(DIM, dtype=np.float32)
    for tok in signature.split():
        h = int(hashlib.md5(tok.encode()).hexdigest(), 16)
        v[h % DIM] += 1.0 if (h >> 9) & 1 else -1.0
    n = np.linalg.norm(v)
    return v / n if n else v


class LocalStore:
    def __init__(self):
        self.items: list[dict] = []

    def add(self, correction_id: int, alert_type: str, signature: str, verdict: str, note: str) -> None:
        self.items.append({"id": correction_id, "type": alert_type, "vec": embed(signature), "verdict": verdict, "note": note, "signature": signature})

    def search(self, alert_type: str, signature: str, k: int = 3) -> list[dict]:
        q = embed(signature)
        scored = [
            {"correction_id": it["id"], "score": float(np.dot(q, it["vec"])), "verdict": it["verdict"], "note": it["note"], "signature": it["signature"]}
            for it in self.items if it["type"] == alert_type
        ]
        scored.sort(key=lambda m: (m["score"], m["correction_id"]), reverse=True)
        return [m for m in scored[:k] if m["score"] > 0.5]

    def clear(self) -> None:
        self.items.clear()


class QdrantStore:
    COLLECTION = "proofladder_corrections"

    def __init__(self, url: str, api_key: str | None):
        from qdrant_client import QdrantClient
        from qdrant_client.models import Distance, VectorParams

        self.client = QdrantClient(url=url, api_key=api_key or None)
        if not self.client.collection_exists(self.COLLECTION):
            self.client.create_collection(self.COLLECTION, vectors_config=VectorParams(size=DIM, distance=Distance.COSINE))

    def add(self, correction_id, alert_type, signature, verdict, note) -> None:
        from qdrant_client.models import PointStruct

        self.client.upsert(self.COLLECTION, points=[PointStruct(
            id=correction_id, vector=embed(signature).tolist(),
            payload={"type": alert_type, "verdict": verdict, "note": note, "signature": signature},
        )])

    def search(self, alert_type, signature, k=3) -> list[dict]:
        from qdrant_client.models import FieldCondition, Filter, MatchValue

        res = self.client.query_points(
            self.COLLECTION, query=embed(signature).tolist(), limit=k,
            query_filter=Filter(must=[FieldCondition(key="type", match=MatchValue(value=alert_type))]),
        ).points
        return [{"correction_id": p.id, "score": float(p.score), "verdict": p.payload["verdict"], "note": p.payload["note"], "signature": p.payload["signature"]} for p in res if p.score > 0.5]

    def clear(self) -> None:
        self.client.delete_collection(self.COLLECTION)
        self.__init__(get_settings().qdrant_url, get_settings().qdrant_api_key)


_store = None


def get_store():
    global _store
    if _store is None:
        s = get_settings()
        _store = QdrantStore(s.qdrant_url, s.qdrant_api_key) if s.memory_backend == "qdrant" else LocalStore()
    return _store
