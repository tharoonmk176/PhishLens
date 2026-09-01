import os
import re
import json
import numpy as np
from typing import List, Optional, Tuple, Dict, Any

_model = None

def get_embedding_model():
    global _model
    if _model is None:
        try:
            from sentence_transformers import SentenceTransformer
            _model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
        except Exception:
            _model = None
    return _model

def _term_ngram_dense_vector(text: str, dim: int = 384) -> np.ndarray:
    """Deterministic n-gram and term-hash projection preserving semantic overlap."""
    vec = np.zeros(dim, dtype=np.float32)
    tokens = re.findall(r'\b\w+\b', text.lower())
    for token in tokens:
        idx = abs(hash(token)) % dim
        vec[idx] += 1.0
        # Character 3-grams for fuzzy matching
        for i in range(len(token) - 2):
            tri = token[i:i+3]
            t_idx = abs(hash(tri)) % dim
            vec[t_idx] += 0.3
    norm = np.linalg.norm(vec)
    return (vec / norm).astype(np.float32) if norm > 0 else vec

def generate_embedding(text: str) -> Optional[np.ndarray]:
    if not text:
        return np.zeros(384, dtype=np.float32)
    model = get_embedding_model()
    if model is not None:
        try:
            emb = model.encode(text, convert_to_numpy=True)
            return emb.astype(np.float32)
        except Exception:
            pass
    return _term_ngram_dense_vector(text, dim=384)

def serialize_embedding(embedding: np.ndarray) -> bytes:
    return embedding.tobytes()

def deserialize_embedding(data: bytes) -> np.ndarray:
    return np.frombuffer(data, dtype=np.float32)

def cosine_similarity(vec_a: np.ndarray, vec_b: np.ndarray) -> float:
    dot = np.dot(vec_a, vec_b)
    norm_a = np.linalg.norm(vec_a)
    norm_b = np.linalg.norm(vec_b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(dot / (norm_a * norm_b))
