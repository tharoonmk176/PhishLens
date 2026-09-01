import os
import json
import numpy as np
from typing import List, Dict, Any
from .embeddings import generate_embedding, deserialize_embedding, cosine_similarity
from storage.duckdb_client import DuckDBClient

class RagRetriever:
    def __init__(self):
        self.db = DuckDBClient()

    def retrieve_relevant_context(self, query_text: str, top_k: int = 3) -> List[Dict[str, Any]]:
        query_vec = generate_embedding(query_text)
        if query_vec is None:
            return []

        candidates = []
        all_records = self.db.get_all_embeddings()

        for rec in all_records:
            emb_blob = rec.get("embedding")
            if not emb_blob:
                continue

            try:
                rec_vec = deserialize_embedding(emb_blob)
                sim = cosine_similarity(query_vec, rec_vec)
                
                source = rec.get("source")
                if source == "threat_pattern":
                    candidates.append({
                        "type": "threat_pattern",
                        "pattern_id": rec.get("pattern_id"),
                        "title": f"Threat Pattern ({rec.get('pattern_id')})",
                        "description": rec.get("description"),
                        "similarity": round(sim, 3)
                    })
                elif source == "analysis":
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
