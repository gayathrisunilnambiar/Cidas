"""Embedding service backed by sentence-transformers + ChromaDB."""
from __future__ import annotations

import asyncio
from functools import lru_cache
from typing import Sequence

from ..config import settings
from .logger import get_logger

log = get_logger(__name__)


@lru_cache(maxsize=1)
def _load_model():
    from sentence_transformers import SentenceTransformer
    log.info("Loading embedding model: %s", settings.embedding_model)
    return SentenceTransformer(settings.embedding_model)


class EmbeddingService:
    """Thin async wrapper around SentenceTransformer."""

    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        model = await asyncio.to_thread(_load_model)
        vectors = await asyncio.to_thread(model.encode, list(texts), show_progress_bar=False)
        return vectors.tolist()

    async def cosine_similarity(self, a: str, b: str) -> float:
        vecs = await self.embed([a, b])
        va, vb = vecs[0], vecs[1]
        dot = sum(x * y for x, y in zip(va, vb))
        norm_a = sum(x ** 2 for x in va) ** 0.5
        norm_b = sum(x ** 2 for x in vb) ** 0.5
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    async def max_similarity(self, query: str, candidates: Sequence[str]) -> float:
        """Return the maximum cosine similarity between query and any candidate."""
        if not candidates:
            return 0.0
        all_texts = [query] + list(candidates)
        vecs = await self.embed(all_texts)
        q_vec = vecs[0]
        norm_q = sum(x ** 2 for x in q_vec) ** 0.5

        max_sim = 0.0
        for c_vec in vecs[1:]:
            dot = sum(x * y for x, y in zip(q_vec, c_vec))
            norm_c = sum(x ** 2 for x in c_vec) ** 0.5
            if norm_q > 0 and norm_c > 0:
                sim = dot / (norm_q * norm_c)
                if sim > max_sim:
                    max_sim = sim
        return max_sim
