import os
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
        except Exception as e:
            # In case model download fails or is offline, fallback embedding
            _model = None
    return _model

def generate_embedding(text: str) -> Optional[np.ndarray]:
    model = get_embedding_model()
    if model is not None:
        emb = model.encode(text, convert_to_numpy=True)
        return emb.astype(np.float32)
    # Fallback 384-dim pseudo embedding for offline/low-resource environments
    np.random.seed(abs(hash(text)) % (2**32))
    vec = np.random.randn(384).astype(np.float32)
    norm = np.linalg.norm(vec)
    return vec / norm if norm > 0 else vec

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
