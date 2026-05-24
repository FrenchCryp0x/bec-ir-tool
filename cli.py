#!/usr/bin/env python3
"""
BEC IR Tool — CLI interface

Usage examples
--------------
  python cli.py ingest audit_log.csv
  python cli.py --case case001 ingest signin_logs.json
  python cli.py search "user~john.doe operation~InboxRule"
  python cli.py search "time>=2024-01-10 type=o365_ual"
  python cli.py timeline --user compromised@corp.com
  python cli.py detections
  python cli.py analyze
  python cli.py stats
  python cli.py serve --port 8080
  python cli.py config set-key sk-ant-...
"""

import json
import sys

import click
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()


# ── Root group ────────────────────────────────────────────────────────────────

@click.group()
@click.option("--case", default="default", show_default=True, help="Investigation case name")
@click.pass_context
def cli(ctx, case):
    """BEC IR Tool — Business Email Compromise investigation platform."""
    ctx.ensure_object(dict)
    ctx.obj["case"] = case


# ── ingest ────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("filepath", type=click.Path(exists=True))
@click.pass_context
def ingest(ctx, filepath):
    """Ingest a log file (CSV, JSON, JSONL, XLS, XLSX)."""
    from app.ingest.parser import ingest as do_ingest
    from app.db import CaseDB
    from app.config import config

    console.print(f"[cyan]Ingesting:[/] {filepath}")
    try:
        df, log_type = do_ingest(filepath)
        db = CaseDB(str(config.case_path(ctx.obj["case"])))
        inserted = db.insert(df)
        db.close()
        console.print(f"[green]✓[/] Log type detected: [bold]{log_type}[/]")
        console.print(f"[green]✓[/] Records ingested:  [bold]{inserted}[/]")
    except Exception as exc:
        console.print(f"[red]ERROR:[/] {exc}")
        sys.exit(1)


# ── search ────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("query", default="*")
@click.option("--limit", default=50, show_default=True)
@click.option("--json-out", is_flag=True, help="Output as JSON")
@click.pass_context
def search(ctx, query, limit, json_out):
    """Search ingested logs.

    \b
    Examples:
      search "user=admin@corp.com"
      search "operation~InboxRule"
      search "ip=203.0.113.5 type=o365_ual"
      search "time>=2024-01-10"
    """
    from app.db import CaseDB
    from app.search import search as do_search, count_results
    from app.config import config

    db = CaseDB(str(config.case_path(ctx.obj["case"])))
    try:
        df    = do_search(db, query, limit)
        total = count_results(db, query)
    except ValueError as exc:
        console.print(f"[red]Query error:[/] {exc}")
        sys.exit(1)
    finally:
        db.close()

    if json_out:
        print(df.to_json(orient="records", date_format="iso", indent=2))
        return

    if df.empty:
        console.print("[yellow]No results.[/]")
        return

    console.print(f"Showing {len(df)} of {total} result(s) for [bold]{query!r}[/]\n")
    tbl = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
    for col in ("timestamp", "user", "operation", "target", "source_ip", "log_type"):
        tbl.add_column(col)

    for _, row in df.iterrows():
        tbl.add_row(
            str(row["timestamp"])[:19],
            (str(row["user"])[:35] or "—"),
            (str(row["operation"])[:40] or "—"),
            (str(row["target"])[:30] or "—"),
            (str(row["source_ip"]) or "—"),
            str(row["log_type"]),
        )
    console.print(tbl)


# ── timeline ──────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--user",      default=None, help="Filter to this user (substring)")
@click.option("--from-time", default=None, help="Start time  e.g. 2024-01-10T08:00")
@click.option("--to-time",   default=None, help="End time    e.g. 2024-01-15T18:00")
@click.option("--limit",     default=300,  show_default=True)
@click.pass_context
def timeline(ctx, user, from_time, to_time, limit):
    """Print chronological event timeline."""
    from app.db import CaseDB
    from app.timeline import build_timeline, detect_bursts
    from app.config import config

    db  = CaseDB(str(config.case_path(ctx.obj["case"])))
    df  = build_timeline(db, user, from_time, to_time, limit)
    db.close()

    if df.empty:
        console.print("[yellow]No events in timeline.[/]")
        return

    bursts = detect_bursts(df)
    if bursts:
        console.print(f"[yellow]⚠ {len(bursts)} suspicious burst(s) detected[/]\n")

    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    for col in ("timestamp", "log_type", "user", "operation", "source_ip"):
        tbl.add_column(col)

    for _, row in df.iterrows():
        tbl.add_row(
            str(row["timestamp"])[:19],
            str(row["log_type"]),
            (str(row["user"])[:35] or "—"),
            (str(row["operation"])[:45] or "—"),
            (str(row["source_ip"]) or "—"),
        )
    console.print(tbl)


# ── detections ────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--json-out", is_flag=True)
@click.pass_context
def detections(ctx, json_out):
    """Run all BEC detection rules against ingested logs."""
    from app.db import CaseDB
    from app.detections import run_all
    from app.config import config

    db       = CaseDB(str(config.case_path(ctx.obj["case"])))
    findings = run_all(db)
    db.close()

    if json_out:
        print(json.dumps(findings, indent=2, default=str))
        return

    if not findings:
        console.print("[green]✓ No detections triggered.[/]")
        return

    _SEV_COLOR = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "white"}

    console.print(f"\n[bold]Found {len(findings)} detection(s):[/]\n")
    for f in findings:
        color = _SEV_COLOR.get(f["severity"], "white")
        console.print(f"  [{color}][{f['severity'].upper()}][/{color}] {f['description']}")
        console.print(f"          rule={f['rule']}  time={f['timestamp'][:19]}")
        if f.get("mitre"):
            console.print(f"          mitre={f['mitre']}")
        console.print()


# ── analyze ───────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--api-key", default=None, envvar="ANTHROPIC_API_KEY",
              help="Anthropic API key (or set ANTHROPIC_API_KEY env var)")
@click.pass_context
def analyze(ctx, api_key):
    """Run AI analysis on ingested logs using the Claude API."""
    from app.db import CaseDB
    from app.analyst import analyze as do_analyze
    from app.config import config

    db = CaseDB(str(config.case_path(ctx.obj["case"])))
    console.print("[cyan]Running AI analysis…[/]  (may take a few seconds)")
    result = do_analyze(db, api_key)
    db.close()

    if result.get("error"):
        console.print(f"[red]ERROR:[/] {result['error']}")
        sys.exit(1)

    console.rule("[bold cyan]AI Analysis[/]")
    console.print(result["analysis"])
    console.rule()
    console.print(
        f"[dim]Tokens: {result.get('input_tokens', 0)} in / "
        f"{result.get('output_tokens', 0)} out[/]"
    )


# ── stats ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
def stats(ctx):
    """Show summary statistics for the current case."""
    from app.db import CaseDB
    from app.config import config

    db = CaseDB(str(config.case_path(ctx.obj["case"])))
    s  = db.stats()
    db.close()

    console.print(f"\n[bold]Case:[/] {ctx.obj['case']}")
    console.print(f"  Total events:  {s['total_events']}")
    console.print(f"  Unique users:  {s['unique_users']}")
    console.print(f"  Log types:     {s['log_type_count']}")
    console.print(f"  Earliest:      {s['earliest']}")
    console.print(f"  Latest:        {s['latest']}\n")


# ── serve ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8080, show_default=True)
def serve(host, port):
    """Start the web dashboard (GUI)."""
    import uvicorn
    console.print(f"[green]BEC IR Tool dashboard → http://{host}:{port}[/]")
    console.print("[dim]Press Ctrl+C to stop.[/]")
    uvicorn.run("app.main:app", host=host, port=port, reload=False)


# ── config ────────────────────────────────────────────────────────────────────

@cli.group("config")
def cfg_group():
    """Configuration commands."""


@cfg_group.command("set-key")
@click.argument("api_key")
def set_key(api_key):
    """Store Anthropic API key in the system keychain."""
    from app.config import config as cfg
    if cfg.set_anthropic_key(api_key):
        console.print("[green]✓ API key stored in keychain.[/]")
    else:
        console.print("[yellow]Keychain unavailable — set ANTHROPIC_API_KEY env var instead.[/]")


@cfg_group.command("show")
def show_config():
    """Show current configuration."""
    from app.config import config as cfg
    console.print(f"Cases directory: {cfg.cases_dir}")
    key = cfg.get_anthropic_key()
    console.print(f"Anthropic key:   {'set (****' + key[-4:] + ')' if key else 'not set'}")


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli(obj={})
