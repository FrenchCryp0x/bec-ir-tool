import duckdb
import pandas as pd

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    timestamp   TIMESTAMP,
    user        VARCHAR,
    operation   VARCHAR,
    target      VARCHAR,
    source_ip   VARCHAR,
    location    VARCHAR,
    result      VARCHAR,
    details     VARCHAR,
    log_type    VARCHAR,
    raw         VARCHAR,
    ingested_at TIMESTAMP DEFAULT current_timestamp
);
"""

_INSERT_COLS = [
    "timestamp", "user", "operation", "target",
    "source_ip", "location", "result", "details", "log_type", "raw",
]


class CaseDB:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = duckdb.connect(db_path)
        self.conn.execute(_CREATE_TABLE)

    def insert(self, df: pd.DataFrame) -> int:
        if df.empty:
            return 0
        subset = df[[c for c in _INSERT_COLS if c in df.columns]].copy()
        for col in _INSERT_COLS:
            if col not in subset.columns:
                subset[col] = None
        subset = subset[_INSERT_COLS]
        before = self._count_all()
        self.conn.register("_insert_tmp", subset)
        self.conn.execute(
            f"INSERT INTO events ({', '.join(_INSERT_COLS)}) SELECT {', '.join(_INSERT_COLS)} FROM _insert_tmp"
        )
        self.conn.unregister("_insert_tmp")
        return self._count_all() - before

    def query(self, sql: str) -> pd.DataFrame:
        return self.conn.execute(sql).df()

    def _count_all(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def stats(self) -> dict:
        row = self.conn.execute("""
            SELECT
                COUNT(*)               AS total_events,
                (SELECT COUNT(DISTINCT user) FROM events
                 WHERE user IS NOT NULL AND user != '' AND LOWER(user) != 'nan'
                ) AS unique_users,
                COUNT(DISTINCT log_type) AS log_type_count,
                MIN(timestamp)         AS earliest,
                MAX(timestamp)         AS latest
            FROM events
        """).fetchone()
        return {
            "total_events":    row[0],
            "unique_users":    row[1],
            "log_type_count":  row[2],
            "earliest":        str(row[3]) if row[3] else None,
            "latest":          str(row[4]) if row[4] else None,
        }

    def close(self):
        self.conn.close()
