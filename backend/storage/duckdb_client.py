import duckdb
import json
import os
import threading
import datetime
from typing import List, Dict, Any, Optional

DB_FILE_PATH = os.environ.get("PHISH_DB_PATH", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "phish_forensics.db"))

class DuckDBClient:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DuckDBClient, cls).__new__(cls)
                cls._instance._init_db()
            return cls._instance

    def _init_db(self):
        try:
            self.conn = duckdb.connect(DB_FILE_PATH, read_only=False)
        except Exception:
            # Fallback to in-memory DB if file is locked or unavailable
            self.conn = duckdb.connect(":memory:")
        self._create_tables()
        self._check_and_auto_seed()

    def _create_tables(self):
        with self._lock:
            # 1. Reference data: known_brand_domains
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS known_brand_domains (
                    brand VARCHAR,
                    legitimate_domain VARCHAR,
                    logo_keywords VARCHAR
                );
            """)

            # 2. Reference data: threat_patterns (embedded at seed time; doubles as RAG corpus)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_patterns (
                    pattern_id VARCHAR PRIMARY KEY,
                    description VARCHAR,
                    embedding BLOB
                );
            """)

            # 3. Analysis history
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS analyses (
                    message_id VARCHAR PRIMARY KEY,
                    from_address VARCHAR,
                    subject VARCHAR,
                    risk_score INTEGER,
                    classification VARCHAR,
                    indicators_json VARCHAR,
                    iocs_json VARCHAR,
                    recommended_action VARCHAR,
                    analyzed_at TIMESTAMP,
                    embedding BLOB
                );
            """)

            # 4. Chat sessions
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS chat_sessions (
                    message_id VARCHAR,
                    turn_index INTEGER,
                    role VARCHAR,
                    content VARCHAR,
                    created_at TIMESTAMP
                );
            """)

    def _check_and_auto_seed(self):
        try:
            cursor = self.conn.execute("SELECT COUNT(*) FROM known_brand_domains")
            count = cursor.fetchone()[0]
            if count == 0:
                self._run_seed()
        except Exception:
            pass

    def _run_seed(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Load brand domains seed
        brands_path = os.path.join(base_dir, "storage", "known_brand_domains_seed.json")
        if not os.path.exists(brands_path):
            brands_path = os.path.join(base_dir, "rag", "corpora", "brand_domains.json")
        
        if os.path.exists(brands_path):
            try:
                with open(brands_path, "r", encoding="utf-8") as f:
                    brands_data = json.load(f)
                normalized_brands = []
                for b in brands_data:
                    brand_name = b.get("brand", "")
                    legit_dom = b.get("legitimate_domain") or (b.get("legitimate_domains", [""])[0] if b.get("legitimate_domains") else "")
                    logo_kws = b.get("logo_keywords") or ",".join(b.get("keywords", []))
                    normalized_brands.append({
                        "brand": brand_name,
                        "legitimate_domain": legit_dom,
                        "logo_keywords": logo_kws
                    })
                
                # Threat patterns
                tp_path = os.path.join(base_dir, "storage", "threat_patterns_seed.json")
                if not os.path.exists(tp_path):
                    tp_path = os.path.join(base_dir, "rag", "corpora", "threat_patterns.json")
                
                normalized_tps = []
                if os.path.exists(tp_path):
                    with open(tp_path, "r", encoding="utf-8") as f:
                        tps_data = json.load(f)
                    
                    from rag.embeddings import generate_embedding, serialize_embedding
                    for idx, tp in enumerate(tps_data):
                        pid = tp.get("pattern_id") or f"THREAT_{idx+1:03d}"
                        desc = tp.get("description") or f"{tp.get('title', '')}: {tp.get('indicators', '')}"
                        emb = generate_embedding(desc)
                        emb_bytes = serialize_embedding(emb) if emb is not None else None
                        normalized_tps.append({
                            "pattern_id": pid,
                            "description": desc,
                            "embedding": emb_bytes
                        })

                self.seed_database(normalized_brands, normalized_tps)
            except Exception:
                pass

    def seed_database(self, known_brands: List[Dict[str, Any]], threat_patterns: List[Dict[str, Any]]):
        with self._lock:
            self.conn.execute("DELETE FROM known_brand_domains;")
            for b in known_brands:
                self.conn.execute("""
                    INSERT INTO known_brand_domains (brand, legitimate_domain, logo_keywords)
                    VALUES (?, ?, ?)
                """, [b.get("brand", ""), b.get("legitimate_domain", ""), b.get("logo_keywords", "")])

            self.conn.execute("DELETE FROM threat_patterns;")
            for tp in threat_patterns:
                self.conn.execute("""
                    INSERT OR REPLACE INTO threat_patterns (pattern_id, description, embedding)
                    VALUES (?, ?, ?)
                """, [tp.get("pattern_id", ""), tp.get("description", ""), tp.get("embedding")])

    def get_known_brand_domains(self) -> List[Dict[str, Any]]:
        with self._lock:
            cursor = self.conn.execute("SELECT brand, legitimate_domain, logo_keywords FROM known_brand_domains")
            rows = cursor.fetchall()
            return [
                {
                    "brand": r[0],
                    "legitimate_domain": r[1],
                    "logo_keywords": r[2] or ""
                }
                for r in rows
            ]

    def get_threat_patterns(self) -> List[Dict[str, Any]]:
        with self._lock:
            cursor = self.conn.execute("SELECT pattern_id, description, embedding FROM threat_patterns")
            rows = cursor.fetchall()
            return [
                {
                    "pattern_id": r[0],
                    "description": r[1],
                    "embedding": r[2]
                }
                for r in rows
            ]

    def save_analysis(self, analysis_result: Dict[str, Any], subject: str = "", from_address: str = "", embedding_bytes: Optional[bytes] = None):
        with self._lock:
            msg_id = analysis_result["message_id"]
            risk_score = analysis_result["risk_score"]
            classification = analysis_result["classification"]
            indicators_json = json.dumps(analysis_result.get("indicators", []))
            iocs_json = json.dumps(analysis_result.get("iocs", {}))
            recommended_action = analysis_result.get("recommended_action", "")
            analyzed_at = analysis_result.get("analyzed_at") or datetime.datetime.now(datetime.timezone.utc).isoformat()

            self.conn.execute("""
                INSERT OR REPLACE INTO analyses (
                    message_id, from_address, subject, risk_score, classification,
                    indicators_json, iocs_json, recommended_action, analyzed_at, embedding
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                msg_id, from_address, subject, risk_score, classification,
                indicators_json, iocs_json, recommended_action, analyzed_at, embedding_bytes
            ])

    def get_analysis(self, message_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            cursor = self.conn.execute("""
                SELECT message_id, from_address, subject, risk_score, classification,
                       indicators_json, iocs_json, recommended_action, analyzed_at
                FROM analyses WHERE message_id = ?
            """, [message_id])
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "message_id": row[0],
                "from_address": row[1],
                "subject": row[2],
                "risk_score": row[3],
                "classification": row[4],
                "indicators": json.loads(row[5]) if row[5] else [],
                "iocs": json.loads(row[6]) if row[6] else {},
                "recommended_action": row[7],
                "analyzed_at": str(row[8])
            }

    def get_all_embeddings(self) -> List[Dict[str, Any]]:
        with self._lock:
            # 1. Threat patterns embeddings
            tp_cursor = self.conn.execute("""
                SELECT pattern_id, description, embedding
                FROM threat_patterns WHERE embedding IS NOT NULL
            """)
            results = []
            for row in tp_cursor.fetchall():
                results.append({
                    "source": "threat_pattern",
                    "pattern_id": row[0],
                    "description": row[1],
                    "embedding": row[2]
                })

            # 2. Past analyses embeddings
            analyses_cursor = self.conn.execute("""
                SELECT message_id, subject, indicators_json, embedding
                FROM analyses WHERE embedding IS NOT NULL
            """)
            for row in analyses_cursor.fetchall():
                results.append({
                    "source": "analysis",
                    "message_id": row[0],
                    "subject": row[1],
                    "indicators_json": row[2],
                    "embedding": row[3]
                })
            return results

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            cursor = self.conn.execute("""
                SELECT message_id, from_address, subject, risk_score, classification,
                       recommended_action, analyzed_at
                FROM analyses
                ORDER BY analyzed_at DESC
                LIMIT ?
            """, [limit])
            rows = cursor.fetchall()
            return [
                {
                    "message_id": r[0],
                    "from_address": r[1],
                    "subject": r[2],
                    "risk_score": r[3],
                    "classification": r[4],
                    "recommended_action": r[5],
                    "analyzed_at": str(r[6])
                }
                for r in rows
            ]

    def save_chat_turn(self, message_id: str, turn_index: int, role: str, content: str):
        with self._lock:
            self.conn.execute("""
                INSERT INTO chat_sessions (message_id, turn_index, role, content, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, [message_id, turn_index, role, content, datetime.datetime.now(datetime.timezone.utc)])

    def get_chat_history(self, message_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            cursor = self.conn.execute("""
                SELECT role, content FROM chat_sessions
                WHERE message_id = ?
                ORDER BY turn_index ASC
            """, [message_id])
            return [{"role": r[0], "content": r[1]} for r in cursor.fetchall()]

    def get_dashboard_stats(self) -> Dict[str, Any]:
        with self._lock:
            # 1. Total counts & classifications
            total_cursor = self.conn.execute("SELECT COUNT(*), AVG(risk_score) FROM analyses")
            total_row = total_cursor.fetchone()
            total_count = total_row[0] if total_row else 0
            avg_risk = round(total_row[1], 1) if total_row and total_row[1] is not None else 0

            class_cursor = self.conn.execute("""
                SELECT classification, COUNT(*) FROM analyses GROUP BY classification
            """)
            class_counts = {r[0]: r[1] for r in class_cursor.fetchall()}

            # 2. Top sender domains / addresses
            sender_cursor = self.conn.execute("""
                SELECT from_address, COUNT(*) as cnt, AVG(risk_score) as avg_score
                FROM analyses
                WHERE from_address IS NOT NULL AND from_address != ''
                GROUP BY from_address
                ORDER BY cnt DESC
                LIMIT 5
            """)
            top_senders = [{"from_address": r[0], "count": r[1], "avg_risk": round(r[2], 1)} for r in sender_cursor.fetchall()]

            # 3. Timeline (daily group)
            timeline_cursor = self.conn.execute("""
                SELECT strftime(analyzed_at, '%Y-%m-%d') as day, COUNT(*), AVG(risk_score)
                FROM analyses
                GROUP BY day
                ORDER BY day ASC
                LIMIT 30
            """)
            timeline = [{"date": r[0], "count": r[1], "avg_risk": round(r[2], 1)} for r in timeline_cursor.fetchall()]

            # 4. Fired indicators rollup
            all_inds_cursor = self.conn.execute("SELECT indicators_json FROM analyses")
            indicator_counts: Dict[str, int] = {}
            for row in all_inds_cursor.fetchall():
                if row[0]:
                    try:
                        inds = json.loads(row[0])
                        for ind in inds:
                            name = ind.get("indicator", "unknown")
                            indicator_counts[name] = indicator_counts.get(name, 0) + 1
                    except Exception:
                        pass
            
            sorted_indicators = sorted([{"indicator": k, "count": v} for k, v in indicator_counts.items()], key=lambda x: x["count"], reverse=True)[:10]

            return {
                "total_analyzed": total_count,
                "average_risk_score": avg_risk,
                "classifications": class_counts,
                "top_senders": top_senders,
                "timeline": timeline,
                "top_indicators": sorted_indicators
            }
