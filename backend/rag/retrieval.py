import os
import json
import numpy as np
from typing import List, Dict, Any
from .embeddings import generate_embedding, deserialize_embedding, cosine_similarity
from storage.duckdb_client import DuckDBClient

class RagRetriever:
    def __init__(self):
        self.db = DuckDBClient()
        self.threat_patterns = self._load_threat_patterns()

    def _load_threat_patterns(self) -> List[Dict[str, Any]]:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(base_dir, "corpora", "threat_patterns.json")
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def retrieve_relevant_context(self, query_text: str, top_k: int = 3) -> List[Dict[str, Any]]:
        query_vec = generate_embedding(query_text)
        candidates = []

        # 1. Match against curated threat patterns
        for tp in self.threat_patterns:
            tp_text = f"{tp.get('title', '')}: {tp.get('description', '')} Indicators: {' '.join(tp.get('indicators', []))}"
            tp_vec = generate_embedding(tp_text)
            sim = cosine_similarity(query_vec, tp_vec)
            candidates.append({
                "type": "threat_pattern",
                "title": tp.get("title"),
                "description": tp.get("description"),
                "similarity": round(sim, 3)
            })

        # 2. Match against past incidents in DuckDB
        past_records = self.db.get_all_embeddings()
        for rec in past_records:
            if rec.get("embedding"):
                try:
                    past_vec = deserialize_embedding(rec["embedding"])
                    sim = cosine_similarity(query_vec, past_vec)
                    candidates.append({
                        "type": "past_incident",
                        "message_id": rec.get("message_id"),
                        "title": f"Past Incident: {rec.get('subject', 'Untitled')}",
                        "description": f"Subject: {rec.get('subject')}, Indicators: {rec.get('indicators_json')}",
                        "similarity": round(sim, 3)
                    })
                except Exception:
                    pass

        # Sort by similarity descending
        candidates.sort(key=lambda x: x["similarity"], reverse=True)
        return candidates[:top_k]
