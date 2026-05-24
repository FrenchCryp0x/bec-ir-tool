# BEC IR Tool — Developer Context

## Project Identity

**Name:** BEC Log Analysis Tool  
**Repo:** `FrenchCryp0x/bec-ir-tool`  
**Owner:** Student DFIR analyst (Western Sydney University)  
**Purpose:** Personal Business Email Compromise (BEC) incident response platform for ingesting M365/Azure AD logs, running rule-based detections, and generating evidence-grade attack summaries.

---

## How to Run

```bash
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

Open http://localhost:8080 in a browser.

**CLI alternative:**
```bash
python cli.py --case default serve
python cli.py --case default detections
python cli.py --case default analyze
```

**Anthropic API key** (required for AI Analysis tab):
```bash
python cli.py config set-key   # stores in system keyring
# or set env var: ANTHROPIC_API_KEY=sk-ant-...
```

---

## Architecture

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI + Uvicorn |
| Database | DuckDB (single-file, no server) |
| Frontend | Vanilla JS SPA (dark theme, no framework) |
| AI | Anthropic Claude (`claude-opus-4-7`) |
| CLI | Click + Rich |

**Data path:** `~/.bec-ir/cases/{case_name}.duckdb`  
**Multi-case:** Each investigation case gets its own DuckDB file.  
**Auto-wipe:** Server startup AND shutdown delete all `.duckdb` files via `lifespan` context manager in `app/main.py`. Browser tab close triggers `POST /api/purge-all` via `navigator.sendBeacon`.

### Normalized Event Schema (10 columns)

All log formats are normalised to this single table before detection rules run:

```
timestamp   TIMESTAMP   — second precision, no microseconds, no timezone
user        VARCHAR     — always UPN (user@domain.com), never display name
operation   VARCHAR     — event type / action performed
target      VARCHAR     — target account or email address
source_ip   VARCHAR     — originating IP (no port suffix)
location    VARCHAR     — city, region string
result      VARCHAR     — Success / Failure / delivery status
details     VARCHAR     — JSON blob, capped at 4000 chars
log_type    VARCHAR     — canonical type tag (see below)
raw         VARCHAR     — original row as JSON
```

**log_type values:**
- `azure_ad_signin` — Azure AD / Entra ID sign-in logs
- `azure_ad_audit` — Azure AD audit logs (role changes, MFA, etc.)
- `o365_ual` — Office 365 Unified Audit Log
- `exchange_mtl` — Exchange message tracking (both hyphen and underscore variants)
- `generic` — Fallback for unrecognised formats

---

## Directory Map

```
app/
  main.py        FastAPI app, all API endpoints, lifespan wipe logic
  config.py      Data paths, case naming, Anthropic key management
  db.py          CaseDB class — DuckDB wrapper, insert/query/stats
  detections.py  11 BEC detection rules, returns sorted findings list
  analyst.py     Claude API integration, DFIR report generation
  search.py      Custom query language → SQL WHERE builder
  timeline.py    Chronological view + burst detection
  ingest/
    parser.py    Auto-detect log format, normalize to 10-col schema

ui/
  index.html     Entire frontend — tabs, JS, CSS in one file

cli.py           Click CLI (ingest, search, timeline, detections, analyze, serve)
requirements.txt 12 Python dependencies
```

---

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | Serve dashboard HTML |
| GET | `/api/cases` | List all cases |
| POST | `/api/cases/{name}` | Create case |
| POST | `/api/purge-all` | Delete all case databases |
| POST | `/api/ingest` | Upload + ingest log file |
| GET | `/api/search` | Query logs (custom query language) |
| GET | `/api/timeline` | Chronological event view |
| GET | `/api/detections` | Run all 11 detection rules |
| POST | `/api/analyze` | Claude AI DFIR report |
| GET | `/api/stats` | Case statistics |
| GET | `/api/users` | Users with activity summary |
| GET | `/api/iocs` | Extracted indicators (IPs, emails) |

---

## Detection Rules

All rules live in `app/detections.py`. `run_all()` calls them all, results sorted by severity.

| Rule | Fires When | Severity | MITRE |
|------|-----------|----------|-------|
| `inbox_rule_created` | `New-InboxRule`, `Set-InboxRule`, `UpdateInboxRules` operations | HIGH | T1114.003 |
| `mailbox_delegation` | `Add-MailboxPermission`, `Add-RecipientPermission` | HIGH | T1114 |
| `oauth_app_grant` | OAuth permission grant or service principal added | HIGH | T1528 |
| `admin_role_added` | `Add member to role` where details mention admin/privileged | CRITICAL | T1098 |
| `mfa_modified` | MFA method added, changed, removed, or disabled | HIGH | T1556 |
| `impossible_travel` | Same user signs in from different locations within 2 hours | CRITICAL | T1078 |
| `offhours_signin` | Sign-ins outside 07:00–20:00, grouped by user+day | LOW | T1078 |
| `mass_email_send` | >50 distinct recipients in 1-hour window | CRITICAL | T1114 |
| `password_reset_by_other` | Admin resets another user's password | HIGH | T1098 |
| `evidence_deletion` | ≥5 mailbox items deleted (MoveToDeletedItems / SoftDelete / HardDelete / Purge) | HIGH or CRITICAL | T1070.008 |
| `large_external_send` | Emails >5 MB to external recipients via Exchange trace | MEDIUM or HIGH | T1048 |

**Severity thresholds:**
- `evidence_deletion` → CRITICAL if any HardDelete, HIGH otherwise
- `large_external_send` → HIGH if >10 emails, MEDIUM otherwise

---

## Attack Summary UI (6 Phases)

The **Attack Summary** tab maps findings to BEC kill-chain phases:

```
Initial Access → Persistence → Privilege Escalation →
Exfiltration → Evidence Cover-up → Account Manipulation
```

**Rule → Phase mapping** (defined in `buildAttackSummary()` in `ui/index.html`):
- Initial Access: `offhours_signin`, `impossible_travel`
- Persistence: `inbox_rule_created`, `mailbox_delegation`, `oauth_app_grant`
- Privilege Escalation: `admin_role_added`, `mfa_modified`
- Exfiltration: `large_external_send`, `mass_email_send`
- Evidence Cover-up: `evidence_deletion`
- Account Manipulation: `password_reset_by_other`

Each phase card shows findings, severity badges, and an IR action checklist.  
**Export CSV** and **Print/PDF** buttons are present on the Attack Summary tab.

**UI tab order:** dashboard → upload → search → timeline → detections → summary → iocs → ai

---

## Supported Log Formats

Auto-detected by column fingerprinting in `app/ingest/parser.py`:

| Format | Detection Signal | Parser Function |
|--------|-----------------|-----------------|
| O365 Unified Audit Log | `AuditData` or `Operations` column | `_norm_o365_ual` |
| Azure AD Sign-in CSV | `UserPrincipalName` + `IPAddress` | `_norm_azure_ad_csv` |
| Azure AD Sign-in JSON | JSON array with `ipAddress` nested | `_norm_azure_ad_json` |
| Azure AD Audit Log | `ActivityDisplayName` column | `_norm_azure_ad_audit` |
| Exchange Message Trace (hyphen cols) | `client-ip`, `recipient-address` | `_norm_exchange_hyphen` |
| Exchange Outbound Trace (underscore cols) | `origin_timestamp_utc`, `sender_address` | `_norm_exchange_trace` |
| Generic | Fallback | `_norm_generic` |

---

## Critical Bug Fixes (DO NOT REVERT)

These were carefully validated against real evidence. Reverting any of them will break accuracy.

### `app/ingest/parser.py`

**1. `_safe_ts` — strip microseconds**
All timestamps must be second-precision. DuckDB timestamps and `str(ts)[:19]` slice in `_finding()` both enforce this. The `_safe_ts` function calls `.replace(microsecond=0)` before returning.

**2. `_norm_azure_ad_csv` — use UPN not display name**
```python
"user": str(row.get("UserPrincipalName") or row.get("Username") or row.get("User") or "")
```
`User` column contains the display name ("Jon Snow"); `UserPrincipalName` contains the UPN ("jon.snow@stark.com"). Detections join on user value — they must be consistent.

**3. `_norm_exchange_trace` — recipient fallback**
Some Exchange exports don't have a `recipient_address` column. The column that exists is `recipient_status` in the format `"email@domain.com##250 2.1.5 OK"`. The code splits on `##` and validates `@` before using the candidate:
```python
recip_addr = str(row.get("recipient_address") or "")
if not recip_addr:
    rs = str(row.get("recipient_status") or "")
    candidate = rs.split("##")[0].strip()
    if "@" in candidate:
        recip_addr = candidate
"target": recip_addr,
```
Without this, all exchange_trace records get `target=""`, which the `large_external_send` filter `target != ''` strips out → Exfiltration phase disappears from Attack Summary.

### `app/db.py`

**4. `stats()` — filter empty/nan users**
The dashboard "Unique Users" count must match what the Users tab shows. The Users tab filters out blank and "nan" user values; `stats()` must use the same filter:
```python
(SELECT COUNT(DISTINCT user) FROM events
 WHERE user IS NOT NULL AND user != '' AND LOWER(user) != 'nan'
) AS unique_users,
```

### `app/detections.py`

**5. `_inbox_rules` — no trailing dots in operation names**
Real O365 UAL operations are `New-InboxRule`, `Set-InboxRule`, `UpdateInboxRules` — no trailing dots. The SQL `IN` list must match exactly what's stored.

**6. `_mfa_modified` — deduplication**
Azure AD fires two audit events for one MFA registration at the exact same second: `Update user.` AND `StrongAuthenticationMethodAdded`. Without dedup, two findings appear for one action. Deduplicate on `(user, timestamp[:19])`, preferring the more specific (non-`update user`) operation.

**7. `_mfa_modified` — MFA keyword gate on `Update user.`**
`Update user.` fires for any Azure AD user attribute change. Only catch it when `details` mentions `StrongAuthentication`, `authentication method`, or `multifactor`.

**8. `_evidence_deletion` — lowercase in IN list**
The query uses `LOWER(operation)` but if the IN list contains mixed case like `'MoveToDeletedItems'`, it never matches. Every value in the IN list must already be lowercase.

**9. `_large_external_send` — email address guard**
```sql
AND target LIKE '%@%'
```
Without this, `recipient_status` values like `"250 2.1.5 OK"` (if the fallback extraction fails) get counted as recipient addresses, inflating the unique recipient count.

**10. `_impossible_travel` — human-readable time**
Display logic:
```python
if secs < 60:    time_str = f"{int(secs)}s"
elif secs < 3600: time_str = f"{int(secs // 60)}m {int(secs % 60)}s"
else:             time_str = f"{hours:.1f} h"
```
Previously used `f"{hours:.1f} h"` for all cases — 78 seconds showed as "0.0 h".

**11. Removed LIMIT clauses**
`_offhours_signin` and `_large_external_send` previously had `LIMIT 30` / `LIMIT 50` which silently capped results. Removed entirely.

---

## Known Log Format Quirks

- **Exchange Outbound Trace** (`_norm_exchange_trace`): target column is `recipient_status` formatted as `"email@domain.com##smtp_code"`, not `recipient_address`. The parser extracts email from before `##`.
- **Azure AD Sign-in CSV**: `User` = display name ("Jon Snow"), `UserPrincipalName` = UPN ("jon.snow@stark.com"). Always use UPN.
- **Azure AD Audit — MFA events**: One user action generates two log entries at the same second. The `_mfa_modified` detector deduplicates them.
- **Exchange MTL vs Exchange Trace**: Both normalise to `log_type = 'exchange_mtl'` so detections work on both variants.

---

## Git Setup Notes

- **Branch:** `main`
- **Commit signing** is disabled locally (`git config --local commit.gpgsign false`) because the Claude Code session signing server is scoped to a different repo (`oplc`). This is intentional — do not remove.
- **Push pattern:** Embed PAT in URL, push, immediately clear:
  ```bash
  git push -u https://TOKEN@github.com/FrenchCryp0x/bec-ir-tool.git main
  git remote set-url origin https://github.com/FrenchCryp0x/bec-ir-tool.git
  ```
  Always revoke the PAT at GitHub → Settings → Developer settings → Personal access tokens after each push.

---

## Validated Test Case

The tool has been validated against a real BEC investigation for `jon.snow@stark.com`. Expected output (15 findings across 5 phases):

| Phase | Count | Key Findings |
|-------|-------|-------------|
| Initial Access | 7 | 2 impossible travel, 5 off-hours sign-in groups |
| Persistence | 5 | 5 inbox rules (all move emails to RSS Feeds, MarkAsRead) |
| Privilege Escalation | 1 | MFA method added/changed (Jun 10) |
| Exfiltration | 1 | 111 large emails to 110 recipients, Mar–Jun 2021 |
| Evidence Cover-up | 1 | 278 mailbox items deleted (5 permanent HardDelete) |

If Exfiltration phase is missing, check Exchange Outbound Trace ingestion — the `recipient_address` column fallback (Fix #3 above).
