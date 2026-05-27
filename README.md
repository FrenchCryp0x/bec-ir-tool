# BEC IR Tool

A lightweight, self-hosted incident response platform for investigating **Business Email Compromise (BEC)** attacks. Built for individual analysts and small teams who need Splunk/Kibana-style log analysis without the enterprise overhead.

---

## Why I Built This

I came straight into IR without going through a SOC role first. My biggest challenge was manually reviewing thousands of log lines across multiple file formats — Azure AD sign-ins, Unified Audit Logs, Exchange message traces — trying to piece together a coherent attack timeline.

This tool ingests all of those formats automatically, runs rule-based detections mapped to MITRE ATT&CK, and produces a phased attack summary you can export as a CSV or PDF. It's not meant to replace existing tools — it's meant to help beginners move faster and think more clearly during an investigation.

---

## Features

- **Multi-format log ingestion** — drag and drop CSV, JSON, JSONL, XLS, or XLSX files; format is auto-detected
- **14 rule-based detections** mapped to MITRE ATT&CK
- **Phased Attack Summary** — maps findings to the BEC kill chain from Initial Access to Containment & Recovery
- **Security Gaps analysis** — automatically flags missing MFA, detection delays, untracked IPs, and early compromise indicators
- **Timeline view** — chronological event view with burst detection
- **Search** — custom query language for filtering across all ingested logs
- **IOCs tab** — extracts and ranks all source IPs with click-through search
- **AI Analysis** — Claude-powered DFIR report with containment steps (requires Anthropic API key)
- **Export** — CSV and print-to-PDF for detections and attack summary
- **GUI and CLI** — browser-based dashboard or terminal interface
- **Privacy-first** — all data is wiped automatically when you close the browser tab or stop the server

---

## Supported Log Formats

| Format | Auto-detected From |
|--------|-------------------|
| O365 Unified Audit Log | `AuditData` or `Operations` column |
| Azure AD Sign-in (CSV) | `UserPrincipalName` + `IPAddress` columns |
| Azure AD Sign-in (JSON) | Nested `ipAddress` field |
| Azure AD Audit Log | `ActivityDisplayName` column |
| Exchange Message Trace | Hyphen-separated column names |
| Exchange Outbound Trace | `origin_timestamp_utc`, `sender_address` columns |
| Generic | Fallback for any other structured log |

---

## Detection Rules

| Rule | Detects | Severity | MITRE |
|------|---------|----------|-------|
| `impossible_travel` | Same account signed in from two locations < 2 hours apart | CRITICAL | T1078 |
| `evidence_deletion` | Bulk mailbox item deletion (MoveToDeletedItems / SoftDelete / HardDelete) | CRITICAL / HIGH | T1070.008 |
| `admin_role_added` | Admin privilege assigned via Azure AD | CRITICAL | T1098 |
| `mass_email_send` | > 50 distinct recipients in a 1-hour window | CRITICAL | T1114 |
| `inbox_rule_created` | New inbox forwarding or filtering rule | HIGH | T1114.003 |
| `mailbox_delegation` | Mailbox permission granted to another account | HIGH | T1114 |
| `oauth_app_grant` | OAuth application permission consented | HIGH | T1528 |
| `mfa_modified` | MFA method added, changed, or removed | HIGH | T1556 |
| `mail_items_accessed` | Mailbox read access (requires advanced auditing) | HIGH | T1114 |
| `password_reset_by_other` | Password reset performed by a different account | HIGH | T1098 |
| `large_external_send` | Large emails (> 5 MB) sent to external recipients | HIGH / MEDIUM | T1048 |
| `account_remediation` | Session revocation or account lockout by IR/admin | MEDIUM | T1078 |
| `offhours_signin` | Sign-ins outside 07:00–20:00, grouped by user and day | LOW | T1078 |
| `gap_*` | Security posture gaps (no prior MFA, MFA delay, untracked IPs, early compromise) | CRITICAL / HIGH | various |

---

## Attack Summary Phases

Findings are automatically mapped to the BEC kill chain:

```
Initial Access → Persistence → Privilege Escalation → Collection →
Exfiltration → Evidence Cover-up → Account Manipulation →
Containment & Recovery → Security Gaps & Risk Factors
```

Each phase card includes the relevant findings and a prioritised IR action checklist.

---

## Quick Start

**Requirements:** Python 3.10+

```bash
git clone https://github.com/FrenchCryp0x/bec-ir-tool.git
cd bec-ir-tool
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8080
```

Open **http://localhost:8080** in your browser.

### CLI

```bash
# Ingest a log file
python cli.py --case mycase ingest logs/signin.csv

# Run detections
python cli.py --case mycase detections

# Search logs
python cli.py --case mycase search "user=jon.snow@stark.com"

# Build timeline
python cli.py --case mycase timeline

# Start the web dashboard
python cli.py --case mycase serve
```

### AI Analysis (optional)

The AI Analysis tab uses the [Anthropic API](https://console.anthropic.com/) to generate a structured DFIR report. You can provide your key two ways:

```bash
# Store in system keyring (recommended)
python cli.py config set-key

# Or set as environment variable
export ANTHROPIC_API_KEY=sk-ant-...
```

Your key is never stored in the database — it is sent only to your local server for the duration of the request.

---

## Running in GitHub Codespaces

No local setup required. Open the repo on GitHub, click **Code → Codespaces → Create codespace on main**, then run:

```bash
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8080
```

Click **Open in Browser** when the port forwarding prompt appears.

---

## Data Privacy

- **On browser tab close** — all case data is wiped via `navigator.sendBeacon`
- **On server start/stop** — all `.duckdb` case files are deleted automatically
- **No data leaves your machine** — everything runs locally; the only external call is to the Anthropic API if you use AI Analysis
- Case databases are stored in `~/.bec-ir/cases/` and are excluded from version control via `.gitignore`

---

## Project Structure

```
app/
  main.py        API endpoints and server lifecycle
  config.py      Data paths and API key management
  db.py          DuckDB wrapper (insert, query, stats)
  detections.py  14 rule-based detection functions
  analyst.py     Claude API integration
  search.py      Custom query language → SQL
  timeline.py    Chronological view and burst detection
  ingest/
    parser.py    Auto-detect and normalise log formats

ui/
  index.html     Full browser dashboard (vanilla JS, dark theme)

cli.py           Click CLI interface
requirements.txt Dependencies
```

---

## Feedback

This is a personal side project built during a DFIR rotation. It has a lot of room to grow. If you're a DFIR analyst and you spot something wrong, missing, or improvable — open an issue or reach out directly. Any feedback is appreciated.
