"""
Simple query language for log search.

  field=value        exact match (case-insensitive)
  field~value        substring match
  field>=value       comparison (timestamps / numbers)
  field=a|b          OR within a field
  freetext           searched across user, operation, target, details

Multiple space-separated terms are AND-ed together.
"""

import re
from typing import Optional
from .db import CaseDB

# Map friendly names → actual DB columns
_FIELD_MAP = {
    "user":      "user",
    "op":        "operation",
    "operation": "operation",
    "action":    "operation",
    "ip":        "source_ip",
    "source_ip": "source_ip",
    "location":  "location",
    "country":   "location",
    "result":    "result",
    "status":    "result",
    "type":      "log_type",
    "log_type":  "log_type",
    "target":    "target",
    "dest":      "target",
    "time":      "timestamp",
    "timestamp": "timestamp",
    "ts":        "timestamp",
}

# Characters allowed in query values (prevent obvious injection)
_SAFE_VALUE = re.compile(r"^[\w@.\-/:,\s\*\|]+$")

_FREE_TEXT_COLS = ["user", "operation", "target", "source_ip", "details"]


def _sanitize(val: str) -> str:
    if not _SAFE_VALUE.match(val):
        raise ValueError(f"Unsafe query value: {val!r}")
    return val.replace("'", "''")  # escape single quotes


def _build_where(query_str: str) -> str:
    if not query_str or query_str.strip() in ("*", ""):
        return "1=1"

    # Tokenise on whitespace but respect quoted strings
    tokens = re.findall(r'(?:[^\s"]+|"[^"]*")+', query_str.strip())
    clauses = []

    for token in tokens:
        m = re.match(r'^(\w+)(~|>=|<=|>|<|=)(.+)$', token)
        if m:
            field_raw, op, value = m.groups()
            value = value.strip('"')
            field = _FIELD_MAP.get(field_raw.lower())
            if not field:
                raise ValueError(f"Unknown field: {field_raw!r}")

            if "|" in value:
                parts = [_sanitize(v) for v in value.split("|")]
                if op == "=":
                    sub = " OR ".join(f"LOWER({field}) = LOWER('{p}')" for p in parts)
                else:
                    sub = " OR ".join(f"LOWER({field}) ILIKE LOWER('%{p}%')" for p in parts)
                clauses.append(f"({sub})")
            else:
                v = _sanitize(value)
                if op == "=":
                    clauses.append(f"LOWER({field}) = LOWER('{v}')")
                elif op == "~":
                    clauses.append(f"LOWER({field}) ILIKE LOWER('%{v}%')")
                else:  # >=, <=, >, <
                    clauses.append(f"{field} {op} '{v}'")
        else:
            # Free-text term
            term = _sanitize(token.strip('"'))
            sub = " OR ".join(
                f"LOWER({col}) ILIKE LOWER('%{term}%')" for col in _FREE_TEXT_COLS
            )
            clauses.append(f"({sub})")

    return " AND ".join(clauses) if clauses else "1=1"


def search(db: "CaseDB", query: str, limit: int = 200, offset: int = 0) -> "pd.DataFrame":
    where = _build_where(query)
    sql = f"""
        SELECT timestamp, user, operation, target, source_ip, location, result, log_type, details
        FROM events
        WHERE {where}
        ORDER BY timestamp DESC
        LIMIT {limit} OFFSET {offset}
    """
    return db.query(sql)


def count_results(db: "CaseDB", query: str) -> int:
    where = _build_where(query)
    return db.conn.execute(f"SELECT COUNT(*) FROM events WHERE {where}").fetchone()[0]
