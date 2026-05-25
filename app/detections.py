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
        _mail_items_accessed,
        _password_reset_by_other,
        _evidence_deletion,
        _large_external_send,
        _account_remediation,
        _security_gaps,
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
    # Normalize timestamp to second precision — no microseconds in forensic findings
    ts = str(timestamp)[:19]
    return {
        "rule":        rule,
        "severity":    severity,
        "user":        str(user),
        "timestamp":   ts,
        "description": description,
        "mitre":       mitre,
        "detail":      str(detail)[:2000],
    }


# ── detection rules ──────────────────────────────────────────────────────────

def _inbox_rules(db: CaseDB) -> list[dict]:
    rows = _rows(db, """
        SELECT user, operation, timestamp, source_ip, details
        FROM events
        WHERE LOWER(operation) IN (
            'new-inboxrule', 'set-inboxrule', 'updateinboxrules'
        )
        ORDER BY timestamp
    """)
    findings = []
    for r in rows:
        op = str(r.get("operation", "")).lower()
        action = "created" if "new" in op or "update" in op else "modified"
        findings.append(_finding(
            "inbox_rule_created", "high",
            r["user"], r["timestamp"],
            f"Inbox rule {action} by {r['user']}",
            "T1114.003 - Email Collection: Email Forwarding Rule",
            r.get("details", ""),
        ))
    return findings


def _mailbox_delegation(db: CaseDB) -> list[dict]:
    rows = _rows(db, """
        SELECT user, operation, timestamp, source_ip, details
        FROM events
        WHERE LOWER(operation) IN (
            'add-mailboxpermission', 'add-recipientpermission',
            'addmailboxpermissions'
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
            'add member to role.', 'add member to role'
        )
          AND (
            LOWER(details) LIKE '%admin%'
            OR LOWER(details) LIKE '%privileged%'
            OR LOWER(details) LIKE '%administrator%'
          )
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
        SELECT user, operation, timestamp, source_ip, details
        FROM events
        WHERE (
            LOWER(operation) IN (
                'strongauthenticationmethodadded',
                'user strongauthenticationrequirement changed',
                'delete user authentication method',
                'disable strong authentication.'
            )
            OR (
                LOWER(operation) IN ('update user.', 'update user')
                AND (
                    LOWER(details) LIKE '%strongauthentication%'
                    OR LOWER(details) LIKE '%authentication method%'
                    OR LOWER(details) LIKE '%multifactor%'
                )
            )
        )
        ORDER BY timestamp
    """)

    # Azure AD fires multiple audit events for one MFA action (e.g. both
    # "Update user." and "StrongAuthenticationMethodAdded" at the same second).
    # Deduplicate on user + second-precision timestamp, keeping the most
    # specific operation (non-'update user' preferred).
    seen: dict = {}
    for r in rows:
        key = (str(r["user"]), str(r["timestamp"])[:19])
        if key not in seen:
            seen[key] = r
        else:
            # prefer the more specific MFA operation over the generic 'update user.'
            existing_op = str(seen[key].get("operation", "")).lower()
            if "update user" in existing_op:
                seen[key] = r

    findings = []
    for r in seen.values():
        op = str(r.get("operation", "")).lower()
        if "delete" in op or "remove" in op or "disable" in op:
            action = "removed/disabled"
        elif "added" in op or "changed" in op or "update" in op:
            action = "added/changed"
        else:
            action = "modified"
        findings.append(_finding(
            "mfa_modified", "high",
            r["user"], r["timestamp"],
            f"MFA method {action} for {r['user']}",
            "T1556 - Modify Authentication Process",
            r.get("details", ""),
        ))
    return findings


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
            secs  = (curr["timestamp"] - prev["timestamp"]).total_seconds()
            hours = secs / 3600
            if (
                0 < hours <= 2
                and prev["location"] != curr["location"]
                and prev["source_ip"] != curr["source_ip"]
            ):
                if secs < 60:
                    time_str = f"{int(secs)}s"
                elif secs < 3600:
                    time_str = f"{int(secs // 60)}m {int(secs % 60)}s"
                else:
                    time_str = f"{hours:.1f} h"
                findings.append(_finding(
                    "impossible_travel", "critical",
                    user, prev["timestamp"],
                    f"Impossible travel: '{prev['location']}' → '{curr['location']}' in {time_str}",
                    "T1078 - Valid Accounts",
                ))

    return findings


def _offhours_signin(db: CaseDB) -> list[dict]:
    """Group off-hours sign-ins by user+day to reduce noise."""
    rows = _rows(db, """
        SELECT
            user,
            CAST(timestamp AS DATE)      AS day,
            COUNT(*)                     AS signin_count,
            MIN(timestamp)               AS first_ts,
            STRING_AGG(DISTINCT location, ', ')   AS locations,
            STRING_AGG(DISTINCT source_ip, ', ')  AS ips
        FROM events
        WHERE (LOWER(log_type) = 'azure_ad_signin' OR LOWER(operation) LIKE '%signin%')
          AND (hour(timestamp) < 7 OR hour(timestamp) >= 20)
          AND user IS NOT NULL AND user != ''
        GROUP BY user, CAST(timestamp AS DATE)
        ORDER BY first_ts
    """)
    return [
        _finding(
            "offhours_signin", "low",
            r["user"], r["first_ts"],
            f"{r['signin_count']} off-hours sign-in(s) by {r['user']} on {str(r['day'])[:10]} from {r.get('locations') or r.get('ips') or 'unknown'}",
            "T1078 - Valid Accounts",
            f"IPs: {r.get('ips','')}",
        )
        for r in rows
    ]


def _mass_email_send(db: CaseDB) -> list[dict]:
    """More than 50 distinct external recipients in a 1-hour window."""
    df = db.query("""
        SELECT user, timestamp, target
        FROM events
        WHERE LOWER(log_type) = 'exchange_mtl'
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
    """Bulk mailbox item deletion across all deletion types — common BEC cover-up."""
    rows = _rows(db, """
        SELECT
            user,
            operation,
            COUNT(*)     AS op_count,
            MIN(timestamp) AS first_ts
        FROM events
        WHERE LOWER(operation) IN (
            'movetodeleteditems', 'movetodeleteditems.',
            'softdelete', 'softdeleteditem',
            'harddeleteditem', 'harddelete', 'harddeletedmessage',
            'purge'
        )
        GROUP BY user, operation
        ORDER BY first_ts
    """)
    if not rows:
        return []

    # Aggregate across all deletion op types per user
    by_user: dict = {}
    for r in rows:
        u = r["user"]
        by_user.setdefault(u, {"total": 0, "ops": {}, "first_ts": r["first_ts"]})
        by_user[u]["total"] += r["op_count"]
        by_user[u]["ops"][r["operation"]] = r["op_count"]
        if r["first_ts"] < by_user[u]["first_ts"]:
            by_user[u]["first_ts"] = r["first_ts"]

    findings = []
    for user, info in by_user.items():
        if info["total"] >= 5:
            ops_summary = ", ".join(f"{op}×{cnt}" for op, cnt in info["ops"].items())
            hard_count = sum(v for k, v in info["ops"].items() if "hard" in k.lower())
            sev = "critical" if hard_count > 0 else "high"
            findings.append(_finding(
                "evidence_deletion", sev,
                user, info["first_ts"],
                f"{user} deleted {info['total']} mailbox items — possible evidence cover-up"
                + (f" ({hard_count} PERMANENT HardDelete)" if hard_count else ""),
                "T1070.008 - Indicator Removal: Clear Mailbox Data",
                ops_summary,
            ))
    return findings


def _mail_items_accessed(db: CaseDB) -> list[dict]:
    """Mailbox read access — shows which emails the attacker collected."""
    rows = _rows(db, """
        SELECT
            user,
            CAST(timestamp AS DATE)              AS day,
            COUNT(*)                             AS access_count,
            MIN(timestamp)                       AS first_ts,
            STRING_AGG(DISTINCT source_ip, ', ') AS ips
        FROM events
        WHERE LOWER(operation) IN ('mailitemsaccessed', 'mail items accessed')
          AND user IS NOT NULL AND user != ''
        GROUP BY user, CAST(timestamp AS DATE)
        ORDER BY first_ts
    """)
    return [
        _finding(
            "mail_items_accessed", "high",
            r["user"], r["first_ts"],
            f"{r['user']} accessed {r['access_count']} mailbox item(s) on {str(r['day'])[:10]}",
            "T1114 - Email Collection",
            f"IPs: {r.get('ips', '')}",
        )
        for r in rows
    ]


def _account_remediation(db: CaseDB) -> list[dict]:
    """IR/admin containment actions — session revocations and account lockouts."""
    rows = _rows(db, """
        SELECT user, operation, timestamp, target, source_ip, details
        FROM events
        WHERE LOWER(operation) IN (
            'revoke refresh tokens for user.',
            'revoke-azureaduserallrefreshtoken',
            'invalidate all active sessions.',
            'disable account.',
            'block sign in.'
        )
        OR (
            LOWER(operation) IN ('update user.', 'update user')
            AND LOWER(details) LIKE '%accountenabled%'
            AND LOWER(details) LIKE '%false%'
        )
        ORDER BY timestamp
    """)
    findings = []
    for r in rows:
        op  = str(r.get("operation", "")).lower()
        det = str(r.get("details", "")).lower()
        if "revoke" in op or "invalidate" in op or "session" in op:
            action = "All sessions revoked"
        elif "disable" in op or "block" in op or "accountenabled" in det:
            action = "Account disabled/blocked"
        else:
            action = "Containment action"
        target_str = str(r.get("target", "") or "")
        desc = f"{action} — actor: {r['user']}"
        if target_str and target_str != str(r["user"]):
            desc += f" | target: {target_str}"
        findings.append(_finding(
            "account_remediation", "medium",
            r["user"], r["timestamp"],
            desc,
            "T1078 - Valid Accounts",
            r.get("details", ""),
        ))
    return findings


def _security_gaps(db: CaseDB) -> list[dict]:
    """Meta-analysis: surface security posture gaps and hardening failures visible in the logs."""
    gaps = []

    # Gap 1: No MFA configured prior to compromise
    mfa_rows = _rows(db, """
        SELECT user, timestamp, details
        FROM events
        WHERE (
            LOWER(operation) IN ('strongauthenticationmethodadded', 'update user.', 'update user')
            AND LOWER(details) LIKE '%strongauthenticationmethod%'
        )
        ORDER BY timestamp
        LIMIT 1
    """)
    for r in mfa_rows:
        try:
            d = json.loads(str(r.get("details", "{}")))
            for prop in d.get("ModifiedProperties", []):
                if prop.get("Name") == "StrongAuthenticationMethod":
                    old = str(prop.get("OldValue", "x")).strip()
                    if old in ("[]", "", "null"):
                        gaps.append(_finding(
                            "gap_no_prior_mfa", "critical",
                            r["user"], r["timestamp"],
                            f"No MFA was configured for {r['user']} prior to compromise — the account was protected by password only",
                            "T1556 - Modify Authentication Process",
                        ))
                    break
        except Exception:
            pass

    # Gap 2: Days between first sign-in activity and MFA enforcement
    tl = _rows(db, """
        SELECT
            MIN(CASE WHEN LOWER(log_type) = 'azure_ad_signin'
                     THEN timestamp END)                                         AS first_signin,
            MAX(CASE WHEN LOWER(operation) IN (
                          'strongauthenticationmethodadded','update user.','update user'
                     ) AND LOWER(details) LIKE '%strongauthenticationmethod%'
                     THEN timestamp END)                                         AS mfa_ts,
            (SELECT user FROM events
             WHERE LOWER(log_type) = 'azure_ad_signin'
               AND user IS NOT NULL AND user != ''
             ORDER BY timestamp LIMIT 1)                                         AS signin_user
        FROM events
    """)
    if tl and tl[0].get("first_signin") and tl[0].get("mfa_ts"):
        row = tl[0]
        try:
            first = pd.to_datetime(row["first_signin"])
            mfa   = pd.to_datetime(row["mfa_ts"])
            days  = (mfa - first).days
            if days > 7:
                gaps.append(_finding(
                    "gap_mfa_delay", "high",
                    str(row.get("signin_user", "") or ""),
                    first,
                    f"MFA was not enforced until {days} days after the first sign-in activity — the account remained vulnerable during this window",
                    "T1556 - Modify Authentication Process",
                ))
        except Exception:
            pass

    # Gap 3: IPs in email/exchange logs not seen in any sign-in log (untracked attacker infrastructure)
    unseen = _rows(db, """
        SELECT e.source_ip, MIN(e.timestamp) AS first_seen
        FROM events e
        WHERE LOWER(e.log_type) = 'exchange_mtl'
          AND e.source_ip IS NOT NULL AND e.source_ip != ''
          AND e.source_ip NOT LIKE '%:%'
          AND e.source_ip NOT IN (
              SELECT DISTINCT source_ip FROM events
              WHERE LOWER(log_type) IN ('azure_ad_signin', 'o365_ual')
                AND source_ip IS NOT NULL AND source_ip != ''
          )
        GROUP BY e.source_ip
        ORDER BY first_seen
    """)
    if unseen:
        ip_list = ", ".join(r["source_ip"] for r in unseen)
        gaps.append(_finding(
            "gap_unseen_exfil_ip", "high",
            "",
            unseen[0]["first_seen"],
            f"{len(unseen)} IP(s) appear in email logs but not in sign-in logs — potential untracked attacker infrastructure: {ip_list}",
            "T1048 - Exfiltration Over Alternative Protocol",
        ))

    # Gap 4: Email exfiltration predates first sign-in log by >30 days (early compromise indicator)
    dates = _rows(db, """
        SELECT
            MIN(CASE WHEN LOWER(log_type) = 'exchange_mtl' THEN timestamp END)  AS first_exfil,
            MIN(CASE WHEN LOWER(log_type) = 'azure_ad_signin' THEN timestamp END) AS first_signin,
            (SELECT user FROM events
             WHERE LOWER(log_type) = 'exchange_mtl'
               AND user IS NOT NULL AND user != ''
             ORDER BY timestamp LIMIT 1)                                          AS exfil_user
        FROM events
    """)
    if dates and dates[0].get("first_exfil") and dates[0].get("first_signin"):
        row = dates[0]
        try:
            exfil  = pd.to_datetime(row["first_exfil"])
            signin = pd.to_datetime(row["first_signin"])
            days_before = (signin - exfil).days
            if days_before > 30:
                gaps.append(_finding(
                    "gap_early_compromise", "critical",
                    str(row.get("exfil_user", "") or ""),
                    exfil,
                    f"Email exfiltration began {days_before} days before the first sign-in log entry — the account may have been compromised well before the known incident window",
                    "T1078 - Valid Accounts",
                ))
        except Exception:
            pass

    return gaps


def _large_external_send(db: CaseDB) -> list[dict]:
    """Group large external sends by user — summarise total count and max size."""
    rows = _rows(db, """
        SELECT
            user,
            COUNT(*)       AS email_count,
            COUNT(DISTINCT target) AS unique_recipients,
            MIN(timestamp) AS first_ts,
            MAX(timestamp) AS last_ts,
            STRING_AGG(DISTINCT source_ip, ', ') AS ips
        FROM events
        WHERE LOWER(log_type) = 'exchange_mtl'
          AND details LIKE '%KB%'
          AND TRY_CAST(regexp_extract(details, '"Size"[^0-9]*(\d+)', 1) AS INTEGER) > 5000
          AND target IS NOT NULL AND target != ''
          AND target LIKE '%@%'
          AND target NOT LIKE '%@%@%'
        GROUP BY user
        ORDER BY email_count DESC
    """)
    return [
        _finding(
            "large_external_send", "high" if r["email_count"] > 10 else "medium",
            r["user"], r["first_ts"],
            f"{r['user']} sent {r['email_count']} large emails (>5 MB) to {r['unique_recipients']} external recipients"
            f" between {str(r['first_ts'])[:10]} and {str(r['last_ts'])[:10]}",
            "T1048 - Exfiltration Over Alternative Protocol",
            f"Source IPs: {r.get('ips','')} | First: {str(r['first_ts'])[:19]} | Last: {str(r['last_ts'])[:19]}",
        )
        for r in rows
    ]
