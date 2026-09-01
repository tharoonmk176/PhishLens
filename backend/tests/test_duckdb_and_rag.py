import pytest
import datetime
from storage.duckdb_client import DuckDBClient
from rag.retrieval import RagRetriever
from rag.embeddings import generate_embedding, serialize_embedding

def test_duckdb_reference_data_and_history():
    db = DuckDBClient()
    
    # 1. Known brand domains
    brands = db.get_known_brand_domains()
    assert len(brands) > 0, "Expected known brand domains table to be seeded"
    paypal_brand = next((b for b in brands if b["brand"].lower() == "paypal"), None)
    assert paypal_brand is not None
    assert "paypal.com" in paypal_brand["legitimate_domain"]

    # 2. Threat patterns
    patterns = db.get_threat_patterns()
    assert len(patterns) > 0, "Expected threat patterns table to be seeded"
    
    # 3. Save analysis and verify persistence
    sample_analysis = {
        "message_id": "test_duckdb_persist_01",
        "risk_score": 85,
        "classification": "HIGH_RISK",
        "indicators": [{"module": "sender_domain", "indicator": "domain_typosquat", "evidence": "paypa1", "weight": 0.9, "confidence": 0.95}],
        "iocs": {"sender_address": "security@paypa1-login.com", "domains": ["paypa1-login.com"], "urls": ["http://paypa1-login.com/verify"], "attachment_hashes": []},
        "recommended_action": "BLOCK_SENDER",
        "analyzed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }
    emb = generate_embedding("Subject: Urgent. Indicators: domain_typosquat")
    db.save_analysis(sample_analysis, subject="Urgent Action", from_address="security@paypa1-login.com", embedding_bytes=serialize_embedding(emb))

    retrieved = db.get_analysis("test_duckdb_persist_01")
    assert retrieved is not None
    assert retrieved["message_id"] == "test_duckdb_persist_01"
    assert retrieved["risk_score"] == 85
    assert retrieved["classification"] == "HIGH_RISK"

    # 4. History list
    history = db.get_history(limit=10)
    assert any(h["message_id"] == "test_duckdb_persist_01" for h in history)

    # 5. Dashboard stats
    stats = db.get_dashboard_stats()
    assert stats["total_analyzed"] >= 1
    assert "HIGH_RISK" in stats["classifications"]

def test_rag_retriever_query():
    retriever = RagRetriever()
    query = "Account suspended within 24 hours enter password at paypal verification link"
    snippets = retriever.retrieve_relevant_context(query, top_k=3)
    assert len(snippets) > 0
    assert any("threat_pattern" in s["type"] or "past_incident" in s["type"] for s in snippets)
    assert all("similarity" in s for s in snippets)
