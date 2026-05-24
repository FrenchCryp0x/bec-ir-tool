"""
Claude API integration for AI-assisted BEC analysis.

Builds a structured context from the ingested logs and detections,
then asks Claude to act as a DFIR analyst and return:
  - Attack chain assessment
  - Severity rating
  - Prioritised containment steps
  - Evidence preservation checklist
  - Post-incident hardening recommendations

Set the ANTHROPIC_API_KEY environment variable or use `bec-ir config set-key`.
"""

from typing import Optional
from .db import CaseDB
from .detections import run_all
from .config import config

_SYSTEM = """You are an expert DFIR (Digital Forensics and Incident Response) analyst
specialising in Business Email Compromise (BEC) investigations with deep knowledge of:
- Microsoft 365, Azure AD / Entra ID attack patterns
- BEC kill chains: initial access → persistence → lateral movement → collection → exfiltration
- MITRE ATT&CK for Enterprise (focus: T1078, T1114, T1528, T1098, T1556, T1566)
- IR playbook steps: containment, eradication, recovery, lessons learned

When responding, structure your output with these exact headers:
## Attack Chain Assessment
## Severity Rating  (Critical / High / Medium / Low + one-sentence justification)
## Containment Steps  (numbered, highest priority first)
## Evidence to Preserve  (bulleted checklist)
## Post-Incident Hardening  (bulleted, specific to M365 / Azure AD)

Be specific. Reference the actual users, operations, and timestamps from the data provided.
Avoid generic advice — tailor every recommendation to what the logs show."""


def _build_prompt(db: CaseDB, detections: list[dict]) -> str:
    stats = db.stats()

    top_ops = db.query("""
        SELECT operation, log_type, COUNT(*) AS cnt
        FROM events
        GROUP BY operation, log_type
        ORDER BY cnt DESC
        LIMIT 15
    """).to_dict("records")

    top_users = db.query("""
        SELECT user, log_type, COUNT(*) AS cnt
        FROM events
        WHERE user != ''
        GROUP BY user, log_type
        ORDER BY cnt DESC
        LIMIT 10
    """).to_dict("records")

    critical = [d for d in detections if d["severity"] == "critical"]
    high     = [d for d in detections if d["severity"] == "high"]
    medium   = [d for d in detections if d["severity"] == "medium"]

    lines = [
        "## Log Statistics",
        f"- Total events: {stats['total_events']}",
        f"- Unique users: {stats['unique_users']}",
        f"- Time range: {stats['earliest']} → {stats['latest']}",
        "",
        f"## Detections Triggered  ({len(detections)} total)",
    ]

    for label, group in (("CRITICAL", critical), ("HIGH", high), ("MEDIUM", medium)):
        if group:
            lines.append(f"\n### {label}")
            for d in group[:8]:
                lines.append(f"- [{d['rule']}] {d['description']}")
                if d.get("mitre"):
                    lines.append(f"  MITRE: {d['mitre']}")
                lines.append(f"  At: {d['timestamp']}")

    lines += [
        "",
        "## Top Operations Observed",
        *[f"- {r['operation']} ({r['log_type']}): {r['cnt']}×" for r in top_ops],
        "",
        "## Most Active Accounts",
        *[f"- {r['user']} ({r['log_type']}): {r['cnt']} events" for r in top_users],
        "",
        "## Task",
        "Based on the above BEC investigation data, provide your full analysis using the required headers.",
    ]

    return "\n".join(lines)


def analyze(db: CaseDB, api_key: Optional[str] = None) -> dict:
    key = api_key or config.get_anthropic_key()
    if not key:
        return {
            "error": (
                "No Anthropic API key found. "
                "Set the ANTHROPIC_API_KEY environment variable, "
                "or run: python cli.py config set-key <YOUR_KEY>"
            ),
            "analysis": None,
        }

    try:
        import anthropic
    except ImportError:
        return {
            "error": "anthropic package not installed. Run: pip install anthropic",
            "analysis": None,
        }

    detections = run_all(db)
    prompt = _build_prompt(db, detections)

    try:
        client = anthropic.Anthropic(api_key=key)
        msg = client.messages.create(
            model="claude-opus-4-7",
            max_tokens=2048,
            system=_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        return {
            "error":           None,
            "analysis":        msg.content[0].text,
            "detections_fed":  len(detections),
            "input_tokens":    msg.usage.input_tokens,
            "output_tokens":   msg.usage.output_tokens,
        }
    except Exception as exc:
        return {"error": str(exc), "analysis": None}
