import duckdb
import json
import os
import threading
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
            # Fallback to in-memory DB if file is locked by another process (e.g. Django server)
            self.conn = duckdb.connect(":memory:")
        self._create_tables()

    def _create_tables(self):
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
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS chat_sessions (
                message_id VARCHAR,
                turn_index INTEGER,
                role VARCHAR,
                content VARCHAR,
                created_at TIMESTAMP
            );
        """)

    def save_analysis(self, analysis_result: Dict[str, Any], subject: str = "", from_address: str = "", embedding_bytes: Optional[bytes] = None):
        with self._lock:
            msg_id = analysis_result["message_id"]
            risk_score = analysis_result["risk_score"]
            classification = analysis_result["classification"]
            indicators_json = json.dumps(analysis_result.get("indicators", []))
            iocs_json = json.dumps(analysis_result.get("iocs", {}))
            recommended_action = analysis_result.get("recommended_action", "")
            analyzed_at = analysis_result.get("analyzed_at")

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
            cursor = self.conn.execute("""
                SELECT message_id, subject, indicators_json, embedding
                FROM analyses WHERE embedding IS NOT NULL
            """)
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append({
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
