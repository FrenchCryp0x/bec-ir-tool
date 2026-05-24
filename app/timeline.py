from typing import Optional
import pandas as pd
from .db import CaseDB


def build_timeline(
    db: CaseDB,
    user: Optional[str] = None,
    from_time: Optional[str] = None,
    to_time: Optional[str] = None,
    limit: int = 1000,
) -> pd.DataFrame:
    conditions = ["1=1"]
    if user:
        safe_user = user.replace("'", "''")
        conditions.append(f"LOWER(user) ILIKE LOWER('%{safe_user}%')")
    if from_time:
        conditions.append(f"timestamp >= '{from_time}'")
    if to_time:
        conditions.append(f"timestamp <= '{to_time}'")

    where = " AND ".join(conditions)
    sql = f"""
        SELECT timestamp, user, operation, target, source_ip, location, result, log_type
        FROM events
        WHERE {where}
        ORDER BY timestamp ASC
        LIMIT {limit}
    """
    return db.query(sql)


def detect_bursts(df: pd.DataFrame, window_minutes: int = 5, sigma: float = 3.0) -> list[dict]:
    """Flag time windows where event rate exceeds mean + sigma*std."""
    if df.empty or len(df) < 10:
        return []

    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    freq = f"{window_minutes}min"
    counts = df.set_index("timestamp").resample(freq).size()
    threshold = counts.mean() + sigma * counts.std()

    findings = []
    for ts, cnt in counts.items():
        if cnt > threshold and threshold > 0:
            findings.append({
                "type":      "activity_burst",
                "timestamp": ts.isoformat(),
                "detail":    f"{int(cnt)} events in {window_minutes}-min window (threshold {int(threshold)})",
                "severity":  "medium",
            })
    return findings
