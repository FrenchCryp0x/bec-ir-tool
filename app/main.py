import os
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse

from .analyst import analyze
from .config import config
from .db import CaseDB
from .detections import run_all
from .ingest.parser import ingest
from .search import count_results, search
from .timeline import build_timeline, detect_bursts

_UI_HTML = Path(__file__).parent.parent / "ui" / "index.html"


def _wipe_all_cases() -> int:
    """Delete every .duckdb file in the cases directory. Returns count deleted."""
    deleted = 0
    for p in config.cases_dir.glob("*.duckdb"):
        try:
            p.unlink()
            deleted += 1
        except Exception:
            pass
    return deleted


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _wipe_all_cases()   # clean up any files left by previous unclean shutdown
    yield
    _wipe_all_cases()   # wipe everything on clean shutdown


app = FastAPI(title="BEC IR Tool", version="0.1.0", docs_url="/api/docs", lifespan=lifespan)


def _open_case(case: str) -> CaseDB:
    return CaseDB(str(config.case_path(case)))


def _ts_safe(records: list[dict]) -> list[dict]:
    """Convert Timestamp objects to ISO strings so JSON serialisation works."""
    out = []
    for r in records:
        row = {}
        for k, v in r.items():
            row[k] = str(v) if hasattr(v, "isoformat") else v
        out.append(row)
    return out


# ── Cases ────────────────────────────────────────────────────────────────────

@app.get("/api/cases")
def list_cases():
    return {"cases": config.list_cases()}


@app.post("/api/purge-all")
def purge_all():
    """Wipe all case databases — called automatically when the browser tab closes."""
    deleted = _wipe_all_cases()
    return {"purged": True, "deleted": deleted}


@app.post("/api/cases/{name}", status_code=201)
def create_case(name: str):
    db = _open_case(name)
    db.close()
    return {"case": name}


# ── Ingest ───────────────────────────────────────────────────────────────────

@app.post("/api/ingest")
async def ingest_file(
    file: UploadFile = File(...),
    case: str = Query(default="default"),
):
    suffix = Path(file.filename or "upload.csv").suffix or ".csv"
    content = await file.read()

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        df, log_type = ingest(tmp_path)
        db = _open_case(case)
        inserted = db.insert(df)
        db.close()
        return {
            "filename":         file.filename,
            "log_type_detected": log_type,
            "records_ingested":  inserted,
            "case":             case,
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    finally:
        os.unlink(tmp_path)


# ── Search ───────────────────────────────────────────────────────────────────

@app.get("/api/search")
def search_events(
    q:      str = Query(default="*"),
    case:   str = Query(default="default"),
    limit:  int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    db = _open_case(case)
    try:
        df    = search(db, q, limit, offset)
        total = count_results(db, q)
        return {
            "results": _ts_safe(df.to_dict("records")),
            "total":   total,
            "limit":   limit,
            "offset":  offset,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    finally:
        db.close()


# ── Timeline ─────────────────────────────────────────────────────────────────

@app.get("/api/timeline")
def get_timeline(
    case:      str           = Query(default="default"),
    user:      Optional[str] = Query(default=None),
    from_time: Optional[str] = Query(default=None),
    to_time:   Optional[str] = Query(default=None),
    limit:     int           = Query(default=500, ge=1, le=5000),
):
    db = _open_case(case)
    try:
        df      = build_timeline(db, user, from_time, to_time, limit)
        bursts  = detect_bursts(df)
        return {
            "timeline":          _ts_safe(df.to_dict("records")),
            "suspicious_bursts": bursts,
            "total":             len(df),
        }
    finally:
        db.close()


# ── Detections ───────────────────────────────────────────────────────────────

@app.get("/api/detections")
def get_detections(case: str = Query(default="default")):
    db = _open_case(case)
    try:
        findings = run_all(db)
        return {"detections": findings, "count": len(findings)}
    finally:
        db.close()


# ── AI Analysis ──────────────────────────────────────────────────────────────

@app.post("/api/analyze")
def ai_analyze(
    case:    str           = Query(default="default"),
    api_key: Optional[str] = Query(default=None),
):
    db = _open_case(case)
    try:
        result = analyze(db, api_key)
        if result.get("error") and not result.get("analysis"):
            raise HTTPException(status_code=503, detail=result["error"])
        return result
    finally:
        db.close()


# ── Stats ────────────────────────────────────────────────────────────────────

@app.get("/api/stats")
def get_stats(case: str = Query(default="default")):
    db = _open_case(case)
    try:
        return db.stats()
    finally:
        db.close()


# ── Users list ───────────────────────────────────────────────────────────────

@app.get("/api/users")
def get_users(case: str = Query(default="default")):
    db = _open_case(case)
    try:
        df = db.query("""
            SELECT
                user,
                COUNT(*)                          AS event_count,
                STRING_AGG(DISTINCT log_type, ', ') AS log_types,
                MIN(timestamp)                    AS first_seen,
                MAX(timestamp)                    AS last_seen
            FROM events
            WHERE user IS NOT NULL AND user != '' AND user != 'nan'
            GROUP BY user
            ORDER BY event_count DESC
            LIMIT 200
        """)
        return {"users": _ts_safe(df.to_dict("records"))}
    finally:
        db.close()


# ── IOCs ─────────────────────────────────────────────────────────────────────

@app.get("/api/iocs")
def get_iocs(case: str = Query(default="default")):
    db = _open_case(case)
    try:
        ips = db.query("""
            SELECT
                source_ip                              AS value,
                COUNT(*)                               AS count,
                COUNT(DISTINCT user)                   AS unique_users,
                STRING_AGG(DISTINCT log_type, ', ')    AS log_types
            FROM events
            WHERE source_ip IS NOT NULL
              AND source_ip NOT IN ('', 'nan', 'None', 'NaN')
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT 30
        """).to_dict("records")
        return {"ips": ips}
    finally:
        db.close()


# ── Serve UI ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def serve_ui():
    if _UI_HTML.exists():
        return _UI_HTML.read_text(encoding="utf-8")
    return "<h1>BEC IR Tool API is running</h1><p>Place ui/index.html to enable the dashboard.</p>"
