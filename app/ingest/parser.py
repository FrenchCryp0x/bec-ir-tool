"""
Auto-detects and normalises log files from:
  - O365 Unified Audit Log (CSV export from Purview)
  - Azure AD / Entra ID Sign-in Logs (CSV or JSON)
  - Exchange Online Message Tracking Logs (CSV)
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

# --- Signature column sets for auto-detection ---

_O365_UAL_SIGS   = {"CreationTime", "UserId", "Operation", "AuditData"}
_AZURE_AD_SIGS   = {"CreatedDateTime", "UserPrincipalName", "AppDisplayName", "ClientAppUsed"}
_AZURE_ALT_SIGS  = {"Date (UTC)", "User", "Authentication requirement", "IP address"}
_EXCHANGE_SIGS   = {"date-time", "sender-address", "recipient-address", "event-id"}
_EXCHANGE_SIGS2  = {"Date-Time", "Sender Address", "Recipient Address", "Event Id"}

_NORMALIZED_COLS = [
    "timestamp", "user", "operation", "target",
    "source_ip", "location", "result", "details", "log_type", "raw",
]


# --- File loading ---

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
        return pd.read_excel(p)
    if ext == ".json":
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        return pd.DataFrame(data if isinstance(data, list) else [data])
    if ext == ".jsonl":
        return pd.read_json(p, lines=True)
    if ext in (".log", ".txt"):
        return pd.read_csv(p, sep=None, engine="python", on_bad_lines="skip")
    raise ValueError(f"Unsupported extension: {ext}")


# --- Auto-detection ---

def _detect_log_type(df: pd.DataFrame) -> str:
    cols = set(df.columns)
    if _O365_UAL_SIGS.issubset(cols):
        return "o365_ual"
    if _AZURE_AD_SIGS.issubset(cols):
        return "azure_ad_signin"
    if _AZURE_ALT_SIGS.issubset(cols):
        return "azure_ad_signin_csv"
    if _EXCHANGE_SIGS.issubset(cols):
        return "exchange_mtl"
    if _EXCHANGE_SIGS2.issubset(cols):
        return "exchange_mtl"
    return "generic"


# --- Timestamp helpers ---

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


# --- Per-format normalisers ---

def _norm_o365_ual(df: pd.DataFrame) -> pd.DataFrame:
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
            target_raw = items[0] if items else ""

        rows.append({
            "timestamp":  _safe_ts(row.get("CreationTime")),
            "user":       str(row.get("UserId", "")),
            "operation":  str(row.get("Operation", "")),
            "target":     str(target_raw),
            "source_ip":  str(ip),
            "location":   str(audit.get("ClientInfoString", "")),
            "result":     str(row.get("ResultStatus", "")),
            "details":    json.dumps({k: v for k, v in audit.items()
                                      if k not in ("AuditData",)}, default=str),
            "log_type":   "o365_ual",
            "raw":        row.to_json(),
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
            "details":   json.dumps({str(k): str(v) for k, v in row.items()}, default=str),
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
            "details":   json.dumps({str(k): str(v) for k, v in row.items()}, default=str),
            "log_type":  "azure_ad_signin",
            "raw":       row.to_json(),
        })
    return pd.DataFrame(rows, columns=_NORMALIZED_COLS)


def _norm_exchange_mtl(df: pd.DataFrame) -> pd.DataFrame:
    # Tolerate both header variants
    col = lambda *names: next((n for n in names if n in df.columns), None)

    ts_col  = col("date-time", "Date-Time", "Timestamp")
    from_col = col("sender-address", "Sender Address", "From")
    to_col  = col("recipient-address", "Recipient Address", "To")
    ev_col  = col("event-id", "Event Id", "EventId")
    ip_col  = col("client-ip", "Client IP", "ClientIP")
    st_col  = col("recipient-status", "Recipient Status", "Status")

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
            "details":    json.dumps({str(k): str(v) for k, v in row.items()}, default=str),
            "log_type":   "exchange_mtl",
            "raw":        row.to_json(),
        })
    return pd.DataFrame(rows, columns=_NORMALIZED_COLS)


def _norm_generic(df: pd.DataFrame) -> pd.DataFrame:
    def _find(keywords):
        return next(
            (c for c in df.columns
             if any(k in c.lower() for k in keywords)),
            None,
        )

    ts_col  = _find(["time", "date", "created", "timestamp"])
    usr_col = _find(["user", "upn", "email", "actor", "account"])
    op_col  = _find(["operation", "action", "event", "activity", "type"])
    ip_col  = _find(["ip", "address", "client"])

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


# --- Public entry point ---

_NORMALIZERS = {
    "o365_ual":          _norm_o365_ual,
    "azure_ad_signin":   _norm_azure_ad_json,
    "azure_ad_signin_csv": _norm_azure_ad_csv,
    "exchange_mtl":      _norm_exchange_mtl,
    "generic":           _norm_generic,
}


def ingest(path: str) -> tuple[pd.DataFrame, str]:
    df_raw  = _load_raw(path)
    log_type = _detect_log_type(df_raw)
    df_norm  = _NORMALIZERS[log_type](df_raw)

    df_norm["timestamp"] = pd.to_datetime(df_norm["timestamp"], errors="coerce", utc=False)
    df_norm = df_norm.dropna(subset=["timestamp"])
    df_norm["timestamp"] = df_norm["timestamp"].dt.tz_localize(None)  # strip tz → naive UTC

    return df_norm, log_type
