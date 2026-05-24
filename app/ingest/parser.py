"""
Auto-detects and normalises log files from:
  - O365 Unified Audit Log (CSV or Excel export from Purview)
  - Azure AD / Entra ID Sign-in Logs (CSV or JSON)
  - Azure AD / Entra ID Audit Logs (Excel/CSV from Entra portal)
  - Exchange Online Message Tracking Logs (CSV, hyphen or underscore variants)
  - Generic structured logs (CSV, JSON, JSONL, XLS, XLSX)

All formats are normalised to the same 10-column schema.
"""

import json
import warnings
from pathlib import Path
from typing import Optional

import pandas as pd
from dateutil import parser as dateparser

warnings.filterwarnings("ignore")


# ── Normalised schema ──────────────────────────────────────────────────────────

_NORMALIZED_COLS = [
    "timestamp", "user", "operation", "target",
    "source_ip", "location", "result", "details", "log_type", "raw",
]


# ── File loading ───────────────────────────────────────────────────────────────

def _load_raw(path: str) -> pd.DataFrame:
    p = Path(path)
    ext = p.suffix.lower()

    if ext == ".csv":
        for enc in ("utf-8-sig", "utf-8", "latin-1"):
            try:
                return pd.read_csv(p, encoding=enc, low_memory=False)
            except Exception:
                continue
        raise ValueError(f"Cannot read CSV: {path}")

    if ext in (".xls", ".xlsx"):
        xl = pd.ExcelFile(p)
        candidates = []
        for sheet in xl.sheet_names:
            try:
                df = xl.parse(sheet)
                if df.shape[0] >= 2 and df.shape[1] >= 3:
                    candidates.append(df)
            except Exception:
                continue
        if not candidates:
            raise ValueError(f"No usable sheet found in: {path}")
        # prefer the sheet that matches a known non-generic log type
        for df in candidates:
            if _detect_log_type(df) != "generic":
                return df
        # fallback: sheet with most rows
        return max(candidates, key=lambda d: d.shape[0])

    if ext == ".json":
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        return pd.DataFrame(data if isinstance(data, list) else [data])

    if ext == ".jsonl":
        return pd.read_json(p, lines=True)

    if ext in (".log", ".txt"):
        return pd.read_csv(p, sep=None, engine="python", on_bad_lines="skip")

    raise ValueError(f"Unsupported extension: {ext}")


# ── Auto-detection ─────────────────────────────────────────────────────────────

def _detect_log_type(df: pd.DataFrame) -> str:
    cols = set(df.columns)

    # O365 UAL — two column-name variants (CSV vs Excel export)
    if "AuditData" in cols and (
        ("CreationTime" in cols or "CreationDate" in cols) and
        ("UserId" in cols or "UserIds" in cols) and
        ("Operation" in cols or "Operations" in cols)
    ):
        return "o365_ual"

    # Azure AD Sign-in JSON export
    if {"CreatedDateTime", "UserPrincipalName", "AppDisplayName", "ClientAppUsed"}.issubset(cols):
        return "azure_ad_signin"

    # Azure AD Sign-in CSV export (from Entra portal)
    if {"Date (UTC)", "User", "Authentication requirement", "IP address"}.issubset(cols):
        return "azure_ad_signin_csv"

    # Azure AD Audit Log (from Entra portal — Activity / Actor columns)
    if {"Date (UTC)", "Activity", "ActorUserPrincipalName"}.issubset(cols):
        return "azure_ad_audit"

    # Exchange MTL — hyphenated columns (legacy)
    if {"date-time", "sender-address", "recipient-address", "event-id"}.issubset(cols):
        return "exchange_mtl"
    if {"Date-Time", "Sender Address", "Recipient Address", "Event Id"}.issubset(cols):
        return "exchange_mtl"

    # Exchange Outbound Message Trace — underscore columns (modern Security portal export)
    if {"origin_timestamp_utc", "sender_address"}.issubset(cols):
        return "exchange_trace"

    return "generic"


# ── Timestamp helper ───────────────────────────────────────────────────────────

def _safe_ts(val) -> Optional[str]:
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return None
    try:
        dt = dateparser.parse(str(val))
        return dt.replace(tzinfo=None).isoformat()
    except Exception:
        return None


def _first_col(df: pd.DataFrame, candidates: list[str]):
    for c in candidates:
        if c in df.columns:
            return c
    return None


# ── Per-format normalisers ─────────────────────────────────────────────────────

def _norm_o365_ual(df: pd.DataFrame) -> pd.DataFrame:
    """O365 Unified Audit Log — handles both CSV (CreationTime/UserId/Operation)
    and Excel export (CreationDate/UserIds/Operations) column variants."""
    ts_col  = _first_col(df, ["CreationTime", "CreationDate"])
    usr_col = _first_col(df, ["UserId", "UserIds"])
    op_col  = _first_col(df, ["Operation", "Operations"])

    rows = []
    for _, row in df.iterrows():
        audit = {}
        raw_ad = row.get("AuditData", "")
        if pd.notna(raw_ad) and raw_ad:
            try:
                audit = json.loads(raw_ad)
            except Exception:
                pass

        ip = audit.get("ClientIP") or audit.get("ActorIpAddress") or ""
        target_raw = audit.get("ObjectId") or ""
        if not target_raw:
            items = audit.get("AffectedItems") or []
            if items and isinstance(items[0], dict):
                target_raw = items[0].get("Subject") or items[0].get("Id") or ""
            elif items:
                target_raw = str(items[0])

        op_val = str(row.get(op_col, "") if op_col else "")
        if not op_val and audit.get("Operation"):
            op_val = audit["Operation"]

        # Build concise details from the most relevant audit fields
        detail_fields = {
            k: v for k, v in audit.items()
            if k not in ("AuditData", "Id", "Version") and v not in (None, "", [])
        }

        rows.append({
            "timestamp": _safe_ts(row.get(ts_col) if ts_col else None) or _safe_ts(audit.get("CreationTime")),
            "user":      str(row.get(usr_col, "") if usr_col else "") or str(audit.get("UserId", "")),
            "operation": op_val,
            "target":    str(target_raw),
            "source_ip": str(ip),
            "location":  str(audit.get("ClientInfoString", "")),
            "result":    str(audit.get("ResultStatus", row.get("ResultStatus", ""))),
            "details":   json.dumps(detail_fields, default=str)[:4000],
            "log_type":  "o365_ual",
            "raw":       row.to_json(),
        })
    return pd.DataFrame(rows, columns=_NORMALIZED_COLS)


def _norm_azure_ad_json(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in df.iterrows():
        loc_parts = []
        for c in ("city", "state", "countryOrRegion", "City", "State", "CountryOrRegion"):
            v = row.get(c)
            if v and pd.notna(v):
                loc_parts.append(str(v))

        status = row.get("status") or row.get("Status") or {}
        if isinstance(status, dict):
            result = "Success" if status.get("errorCode") == 0 else f"Fail({status.get('errorCode')})"
        else:
            result = str(status)

        rows.append({
            "timestamp": _safe_ts(row.get("createdDateTime") or row.get("CreatedDateTime")),
            "user":      str(row.get("userPrincipalName") or row.get("UserPrincipalName") or ""),
            "operation": f"SignIn:{row.get('appDisplayName') or row.get('AppDisplayName') or 'Unknown'}",
            "target":    str(row.get("appDisplayName") or row.get("AppDisplayName") or ""),
            "source_ip": str(row.get("ipAddress") or row.get("IPAddress") or ""),
            "location":  ", ".join(loc_parts) or str(row.get("location") or ""),
            "result":    result,
            "details":   json.dumps({str(k): str(v) for k, v in row.items()}, default=str)[:4000],
            "log_type":  "azure_ad_signin",
            "raw":       row.to_json(),
        })
    return pd.DataFrame(rows, columns=_NORMALIZED_COLS)


def _norm_azure_ad_csv(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in df.iterrows():
        rows.append({
            "timestamp": _safe_ts(row.get("Date (UTC)") or row.get("CreatedDateTime")),
            "user":      str(row.get("User") or row.get("Username") or ""),
            "operation": f"SignIn:{row.get('App') or row.get('Application') or 'Unknown'}",
            "target":    str(row.get("App") or row.get("Application") or ""),
            "source_ip": str(row.get("IP address") or row.get("IPAddress") or ""),
            "location":  str(row.get("Location") or ""),
            "result":    str(row.get("Status") or row.get("Result") or ""),
            "details":   json.dumps({str(k): str(v) for k, v in row.items()}, default=str)[:4000],
            "log_type":  "azure_ad_signin",
            "raw":       row.to_json(),
        })
    return pd.DataFrame(rows, columns=_NORMALIZED_COLS)


def _norm_azure_audit(df: pd.DataFrame) -> pd.DataFrame:
    """Azure AD / Entra ID Audit Log (Excel export from Entra portal).
    Key columns: Date (UTC), Service, Category, Activity, Result,
    ActorUserPrincipalName, IPAddress, Target1UserPrincipalName,
    Target1ModifiedProperty1Name/OldValue/NewValue, ..."""
    rows = []
    for _, row in df.iterrows():
        # Collect changed properties into a readable dict
        changes = {}
        for i in range(1, 6):
            prop = row.get(f"Target1ModifiedProperty{i}Name")
            new  = row.get(f"Target1ModifiedProperty{i}NewValue")
            old  = row.get(f"Target1ModifiedProperty{i}OldValue")
            if pd.notna(prop) and prop:
                changes[str(prop)] = {"old": str(old) if pd.notna(old) else "", "new": str(new) if pd.notna(new) else ""}

        # Additional details
        additional = {}
        for i in range(1, 7):
            k = row.get(f"AdditionalDetail{i}Key")
            v = row.get(f"AdditionalDetail{i}Value")
            if pd.notna(k) and k:
                additional[str(k)] = str(v) if pd.notna(v) else ""

        target = str(row.get("Target1UserPrincipalName") or row.get("Target1DisplayName") or "")

        details_obj = {
            "Service":   str(row.get("Service") or ""),
            "Category":  str(row.get("Category") or ""),
            "ResultReason": str(row.get("ResultReason") or ""),
            "Target":    target,
            "Actor":     str(row.get("ActorDisplayName") or ""),
        }
        if changes:
            details_obj["Changes"] = changes
        if additional:
            details_obj["Additional"] = additional

        rows.append({
            "timestamp": _safe_ts(row.get("Date (UTC)")),
            "user":      str(row.get("ActorUserPrincipalName") or row.get("ActorDisplayName") or ""),
            "operation": str(row.get("Activity") or ""),
            "target":    target,
            "source_ip": str(row.get("IPAddress") or ""),
            "location":  "",
            "result":    str(row.get("Result") or ""),
            "details":   json.dumps(details_obj, default=str)[:4000],
            "log_type":  "azure_ad_audit",
            "raw":       row.to_json(),
        })
    return pd.DataFrame(rows, columns=_NORMALIZED_COLS)


def _norm_exchange_mtl(df: pd.DataFrame) -> pd.DataFrame:
    """Exchange Online Message Tracking Log — hyphenated column variant."""
    col = lambda *names: next((n for n in names if n in df.columns), None)

    ts_col   = col("date-time", "Date-Time", "Timestamp")
    from_col = col("sender-address", "Sender Address", "From")
    to_col   = col("recipient-address", "Recipient Address", "To")
    ev_col   = col("event-id", "Event Id", "EventId")
    ip_col   = col("client-ip", "Client IP", "ClientIP")
    st_col   = col("recipient-status", "Recipient Status", "Status")

    rows = []
    for _, row in df.iterrows():
        rows.append({
            "timestamp":  _safe_ts(row.get(ts_col) if ts_col else None),
            "user":       str(row.get(from_col) if from_col else ""),
            "operation":  f"EMAIL:{row.get(ev_col, 'SEND') if ev_col else 'SEND'}",
            "target":     str(row.get(to_col) if to_col else ""),
            "source_ip":  str(row.get(ip_col) if ip_col else ""),
            "location":   "",
            "result":     str(row.get(st_col) if st_col else ""),
            "details":    json.dumps({str(k): str(v) for k, v in row.items()}, default=str)[:4000],
            "log_type":   "exchange_mtl",
            "raw":        row.to_json(),
        })
    return pd.DataFrame(rows, columns=_NORMALIZED_COLS)


def _norm_exchange_trace(df: pd.DataFrame) -> pd.DataFrame:
    """Exchange Outbound Message Trace — underscore column variant
    (modern Security & Compliance portal export)."""
    rows = []
    for _, row in df.iterrows():
        subject = str(row.get("message_subject") or "")
        size_kb = ""
        tb = row.get("total_bytes")
        if pd.notna(tb):
            try:
                size_kb = f"{int(tb)//1024} KB"
            except Exception:
                pass

        details_obj = {
            "Subject":    subject,
            "Size":       size_kb,
            "MessageId":  str(row.get("message_id") or ""),
            "Direction":  str(row.get("directionality") or ""),
            "Priority":   str(row.get("delivery_priority") or ""),
            "Connector":  str(row.get("connector_id") or ""),
        }

        rows.append({
            "timestamp": _safe_ts(row.get("origin_timestamp_utc")),
            "user":      str(row.get("sender_address") or ""),
            "operation": "EMAIL:SEND",
            "target":    str(row.get("recipient_status") or ""),  # contains recipient email
            "source_ip": str(row.get("original_client_ip") or ""),
            "location":  "",
            "result":    str(row.get("delivery_priority") or ""),
            "details":   json.dumps(details_obj, default=str),
            "log_type":  "exchange_mtl",  # same logical type for detections
            "raw":       row.to_json(),
        })
    return pd.DataFrame(rows, columns=_NORMALIZED_COLS)


def _norm_generic(df: pd.DataFrame) -> pd.DataFrame:
    def _find(keywords):
        return next(
            (c for c in df.columns if any(k in c.lower() for k in keywords)),
            None,
        )

    ts_col  = _find(["time", "date", "created", "timestamp"])
    usr_col = _find(["user", "upn", "email", "actor", "account", "sender"])
    op_col  = _find(["operation", "action", "event", "activity"])
    ip_col  = _find(["clientip", "sourceip", "ipaddress", "client_ip", "source_ip"])
    if not ip_col:
        ip_col = _find(["ip"])

    rows = []
    for _, row in df.iterrows():
        rows.append({
            "timestamp": _safe_ts(row.get(ts_col) if ts_col else None),
            "user":      str(row.get(usr_col) if usr_col else ""),
            "operation": str(row.get(op_col)  if op_col  else "UNKNOWN"),
            "target":    "",
            "source_ip": str(row.get(ip_col)  if ip_col  else ""),
            "location":  "",
            "result":    "",
            "details":   row.to_json(),
            "log_type":  "generic",
            "raw":       row.to_json(),
        })
    return pd.DataFrame(rows, columns=_NORMALIZED_COLS)


# ── Public entry point ────────────────────────────────────────────────────────

_NORMALIZERS = {
    "o365_ual":            _norm_o365_ual,
    "azure_ad_signin":     _norm_azure_ad_json,
    "azure_ad_signin_csv": _norm_azure_ad_csv,
    "azure_ad_audit":      _norm_azure_audit,
    "exchange_mtl":        _norm_exchange_mtl,
    "exchange_trace":      _norm_exchange_trace,
    "generic":             _norm_generic,
}


def ingest(path: str) -> tuple[pd.DataFrame, str]:
    df_raw   = _load_raw(path)
    log_type = _detect_log_type(df_raw)
    df_norm  = _NORMALIZERS[log_type](df_raw)

    df_norm["timestamp"] = pd.to_datetime(df_norm["timestamp"], errors="coerce", utc=False)
    df_norm = df_norm.dropna(subset=["timestamp"])
    df_norm["timestamp"] = df_norm["timestamp"].dt.tz_localize(None)

    return df_norm, log_type
