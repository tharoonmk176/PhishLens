import os
import sys
import json
import numpy as np

# Ensure backend root is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from storage.duckdb_client import DuckDBClient
from rag.embeddings import generate_embedding, serialize_embedding

def seed_duckdb():
    print("Starting DuckDB reference data seeding...")
    db = DuckDBClient()
    
    # 1. Load known brand domains seed
    brands_seed_path = os.path.join(BASE_DIR, "storage", "known_brand_domains_seed.json")
    if not os.path.exists(brands_seed_path):
        # Fallback to rag/corpora/brand_domains.json if exists
        alt_path = os.path.join(BASE_DIR, "rag", "corpora", "brand_domains.json")
        if os.path.exists(alt_path):
            brands_seed_path = alt_path

    with open(brands_seed_path, "r", encoding="utf-8") as f:
        raw_brands = json.load(f)

    # Normalize brands data
    normalized_brands = []
    for b in raw_brands:
        brand_name = b.get("brand", "")
        legit_dom = b.get("legitimate_domain") or (b.get("legitimate_domains", [""])[0] if b.get("legitimate_domains") else "")
        logo_kws = b.get("logo_keywords")
        if not logo_kws:
            kw_list = b.get("keywords", [])
            logo_kws = ",".join(kw_list)
        normalized_brands.append({
            "brand": brand_name,
            "legitimate_domain": legit_dom,
            "logo_keywords": logo_kws
        })

    # 2. Load threat patterns seed
    patterns_seed_path = os.path.join(BASE_DIR, "storage", "threat_patterns_seed.json")
    if not os.path.exists(patterns_seed_path):
        alt_tp = os.path.join(BASE_DIR, "rag", "corpora", "threat_patterns.json")
        if os.path.exists(alt_tp):
            patterns_seed_path = alt_tp

    with open(patterns_seed_path, "r", encoding="utf-8") as f:
        raw_patterns = json.load(f)

    # Normalize threat patterns and compute embeddings at seed time
    seeded_patterns = []
    print(f"Computing embeddings for {len(raw_patterns)} threat patterns at seed time...")
    for idx, tp in enumerate(raw_patterns):
        pid = tp.get("pattern_id") or f"THREAT_{idx+1:03d}"
        desc = tp.get("description") or f"{tp.get('title', '')}: {tp.get('indicators', '')}"
        
        # Compute embedding at seed time
        emb = generate_embedding(desc)
        emb_bytes = serialize_embedding(emb) if emb is not None else None
        
        seeded_patterns.append({
            "pattern_id": pid,
            "description": desc,
            "embedding": emb_bytes
        })

    # 3. Seed into DuckDB tables
    db.seed_database(normalized_brands, seeded_patterns)
    print(f"Successfully seeded {len(normalized_brands)} known brand domains and {len(seeded_patterns)} threat patterns into DuckDB!")

if __name__ == "__main__":
    seed_duckdb()
