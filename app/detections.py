"""
Rule-based BEC detection engine.

Each detector returns a list of finding dicts:
  rule, severity, user, timestamp, description, mitre (optional), detail (optional)
"""

import json
import pandas as pd
from .db import CaseDB

_SEVERITIES = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def run_all(db: CaseDB) -> list[dict]:
    findings: list[dict] = []
    for fn in (
        _inbox_rules,
        _mailbox_delegation,
        _oauth_grants,
        _admin_role_added,
        _mfa_modified,
        _impossible_travel,
        _offhours_signin,
        _mass_email_send,
        _password_reset_by_other,
        _evidence_deletion,
        _large_external_send,
    ):
        try:
            findings.extend(fn(db))
        except Exception:
            pass

    findings.sort(key=lambda f: _SEVERITIES.get(f.get("severity", "low"), 99))
    return findings


# ── helpers ──────────────────────────────────────────────────────────────────

def _rows(db: CaseDB, sql: str) -> list[dict]:
    return db.query(sql).to_dict("records")


def _finding(rule, severity, user, timestamp, description, mitre="", detail="") -> dict:
    return {
        "rule":        rule,
        "severity":    severity,
        "user":        str(user),
        "timestamp":   str(timestamp),
        "description": description,
        "mitre":       mitre,
        "detail":      str(detail)[:300],
    }


# ── detection rules ──────────────────────────────────────────────────────────

def _inbox_rules(db: CaseDB) -> list[dict]:
    rows = _rows(db, """
        SELECT user, operation, timestamp, source_ip, details
        FROM events
        WHERE LOWER(operation) IN (
            'new-inboxrule', 'set-inboxrule', 'updateinboxrules',
            'new-inboxrule.', 'set-inboxrule.'
        )
        ORDER BY timestamp
    """)
    return [
        _finding(
            "inbox_rule_created", "high",
            r["user"], r["timestamp"],
            f"Inbox rule created/modified by {r['user']}",
            "T1114.003 - Email Collection: Email Forwarding Rule",
            r.get("details", ""),
        )
        for r in rows
    ]


def _mailbox_delegation(db: CaseDB) -> list[dict]:
    rows = _rows(db, """
        SELECT user, operation, timestamp, source_ip, details
        FROM events
        WHERE LOWER(operation) IN (
            'add-mailboxpermission', 'add-recipientpermission',
            'addmailboxpermissions', 'add-mailboxpermission.'
        )
        ORDER BY timestamp
    """)
    return [
        _finding(
            "mailbox_delegation", "high",
            r["user"], r["timestamp"],
            f"Mailbox access delegation set by {r['user']}",
            "T1114 - Email Collection",
            r.get("details", ""),
        )
        for r in rows
    ]


def _oauth_grants(db: CaseDB) -> list[dict]:
    rows = _rows(db, """
        SELECT user, operation, timestamp, source_ip, details
        FROM events
        WHERE LOWER(operation) IN (
            'add oauth2permissiongrant.',
            'consent to application',
            'add service principal',
            'add delegated permission grant.'
        )
        ORDER BY timestamp
    """)
    return [
        _finding(
            "oauth_app_grant", "high",
            r["user"], r["timestamp"],
            f"OAuth application permission granted by {r['user']}",
            "T1528 - Steal Application Access Token",
            r.get("details", ""),
        )
        for r in rows
    ]


def _admin_role_added(db: CaseDB) -> list[dict]:
    rows = _rows(db, """
        SELECT user, operation, timestamp, source_ip, details
        FROM events
        WHERE LOWER(operation) IN (
            'add member to role.', 'add user.',
            'set user.', 'add delegated permission grant.'
        )
          AND LOWER(details) LIKE '%admin%'
        ORDER BY timestamp
    """)
    return [
        _finding(
            "admin_role_added", "critical",
            r["user"], r["timestamp"],
            f"Admin privilege assigned (actor: {r['user']})",
            "T1098 - Account Manipulation",
            r.get("details", ""),
        )
        for r in rows
    ]


def _mfa_modified(db: CaseDB) -> list[dict]:
    rows = _rows(db, """
        SELECT user, operation, timestamp, source_ip
        FROM events
        WHERE LOWER(operation) IN (
            'strongauthenticationmethodadded',
            'user strongauthenticationrequirement changed',
            'delete user authentication method',
            'update user.',
            'disable strong authentication.'
        )
        ORDER BY timestamp
    """)
    return [
        _finding(
            "mfa_modified", "high",
            r["user"], r["timestamp"],
            f"MFA method added/removed for {r['user']}",
            "T1556 - Modify Authentication Process",
        )
        for r in rows
    ]


def _impossible_travel(db: CaseDB) -> list[dict]:
    """Flag same user signing in from different locations < 2 h apart."""
    df = db.query("""
        SELECT user, timestamp, location, source_ip
        FROM events
        WHERE (LOWER(log_type) = 'azure_ad_signin' OR LOWER(operation) LIKE '%signin%')
          AND location IS NOT NULL AND location != ''
        ORDER BY user, timestamp
    """)
    if df.empty:
        return []

    df["timestamp"] = pd.to_datetime(df["timestamp"])
    findings = []

    for user, grp in df.groupby("user"):
        grp = grp.sort_values("timestamp").reset_index(drop=True)
        for i in range(1, len(grp)):
            prev, curr = grp.iloc[i - 1], grp.iloc[i]
            hours = (curr["timestamp"] - prev["timestamp"]).total_seconds() / 3600
            if (
                0 < hours <= 2
                and prev["location"] != curr["location"]
                and prev["source_ip"] != curr["source_ip"]
            ):
                findings.append(_finding(
                    "impossible_travel", "critical",
                    user, prev["timestamp"],
                    f"Impossible travel: '{prev['location']}' → '{curr['location']}' in {hours:.1f} h",
                    "T1078 - Valid Accounts",
                ))

    return findings


def _offhours_signin(db: CaseDB) -> list[dict]:
    rows = _rows(db, """
        SELECT user, timestamp, source_ip, location
        FROM events
        WHERE (LOWER(log_type) = 'azure_ad_signin' OR LOWER(operation) LIKE '%signin%')
          AND (hour(timestamp) < 7 OR hour(timestamp) >= 20)
        ORDER BY timestamp
        LIMIT 50
    """)
    return [
        _finding(
            "offhours_signin", "low",
            r["user"], r["timestamp"],
            f"Sign-in outside business hours by {r['user']} from {r.get('location') or r.get('source_ip') or 'unknown'}",
            "T1078 - Valid Accounts",
        )
        for r in rows
    ]


def _mass_email_send(db: CaseDB) -> list[dict]:
    """More than 50 distinct external recipients in a 1-hour window."""
    df = db.query("""
        SELECT user, timestamp, target
        FROM events
        WHERE log_type = 'exchange_mtl'
          AND target IS NOT NULL AND target != ''
        ORDER BY user, timestamp
    """)
    if df.empty:
        return []

    df["timestamp"] = pd.to_datetime(df["timestamp"])
    findings = []

    for user, grp in df.groupby("user"):
        grp = grp.set_index("timestamp").sort_index()
        rolling = grp["target"].resample("1h").nunique()
        bursts = rolling[rolling > 50]
        for ts, cnt in bursts.items():
            findings.append(_finding(
                "mass_email_send", "critical",
                user, ts,
                f"{user} sent to {int(cnt)} distinct recipients in 1 h",
                "T1114 - Email Collection",
            ))

    return findings


def _password_reset_by_other(db: CaseDB) -> list[dict]:
    rows = _rows(db, """
        SELECT user, operation, timestamp, target, details
        FROM events
        WHERE LOWER(operation) IN (
            'reset user password.', 'change user password.',
            'resetpassword', 'changepassword'
        )
          AND user != target AND target IS NOT NULL AND target != ''
        ORDER BY timestamp
    """)
    return [
        _finding(
            "password_reset_by_other", "high",
            r["user"], r["timestamp"],
            f"Password reset by {r['user']} on account {r.get('target', '?')}",
            "T1098 - Account Manipulation",
            r.get("details", ""),
        )
        for r in rows
    ]


def _evidence_deletion(db: CaseDB) -> list[dict]:
    """Bulk mailbox item deletion — common BEC cover-up after access."""
    rows = _rows(db, """
        SELECT user, timestamp, operation, COUNT(*) OVER (PARTITION BY user) AS total
        FROM events
        WHERE LOWER(operation) IN (
            'movetodeletedItems', 'movetodeletedItems.',
            'softdelete', 'harddeleteditem', 'purge'
        )
        ORDER BY timestamp
        LIMIT 200
    """)
    if not rows:
        return []

    # group by user, flag if > 10 deletion events
    by_user: dict = {}
    for r in rows:
        u = r["user"]
        by_user.setdefault(u, []).append(r)

    findings = []
    for user, evs in by_user.items():
        if len(evs) >= 5:
            findings.append(_finding(
                "evidence_deletion", "high",
                user, evs[0]["timestamp"],
                f"{user} performed {len(evs)} mailbox deletion operation(s) — possible evidence cover-up",
                "T1070.008 - Indicator Removal: Clear Mailbox Data",
                f"Operations: {', '.join(set(e['operation'] for e in evs))}",
            ))
    return findings


def _large_external_send(db: CaseDB) -> list[dict]:
    """Emails with large attachments sent externally — possible data exfiltration."""
    rows = _rows(db, """
        SELECT user, timestamp, target, details
        FROM events
        WHERE log_type = 'exchange_mtl'
          AND details LIKE '%KB%'
          AND CAST(regexp_extract(details, '"Size":\s*"(\d+)', 1) AS INTEGER) > 5000
          AND target IS NOT NULL AND target != ''
        ORDER BY timestamp
        LIMIT 50
    """)
    return [
        _finding(
            "large_external_send", "medium",
            r["user"], r["timestamp"],
            f"{r['user']} sent a large email ({r.get('details','')[:80]}) to external recipient",
            "T1048 - Exfiltration Over Alternative Protocol",
            r.get("details", ""),
        )
        for r in rows
    ]
