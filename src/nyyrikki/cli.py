"""Command-line interface: nyyrikki scan FILE [--json] [--out REPORT.json]."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from nyyrikki import __version__
from nyyrikki.events import ParseError, load_events
from nyyrikki.explain import DEFAULT_OLLAMA_URL, ExplainError, explain, ollama_generator
from nyyrikki.report import build_report, to_json, to_text
from nyyrikki.rules import run_rules


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nyyrikki",
        description="Identify potentially suspicious activity in exported Windows Security events.",
    )
    parser.add_argument("--version", action="version", version=f"nyyrikki {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan an event XML file and report findings")
    scan.add_argument("file", help="event XML exported with wevtutil or Event Viewer")
    scan.add_argument("--json", action="store_true", help="print the structured JSON report instead of the summary")
    scan.add_argument("--out", metavar="REPORT.json", help="also save the JSON report to this local file (never overwritten)")
    scan.add_argument("--explain", action="store_true", help="ask a local model to explain each finding")
    scan.add_argument("--model", help="local Ollama model name (required with --explain)")
    scan.add_argument("--ollama-url", default=DEFAULT_OLLAMA_URL, help="local Ollama URL (localhost only)")
    return parser


def _error(message: str) -> int:
    print(f"nyyrikki: {message}", file=sys.stderr)
    return 2


def _save(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:  # "x": fail if it exists
        handle.write(content)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.explain and not args.model:
        parser.error("--explain requires --model")

    out_path = Path(args.out) if args.out else None
    if out_path is not None and out_path.exists():
        return _error(f"{out_path} already exists; refusing to overwrite it")

    try:
        events = load_events(args.file)
    except ParseError as exc:
        return _error(str(exc))

    findings = run_rules(events)

    if args.explain:
        try:
            generate = ollama_generator(args.model, args.ollama_url)
        except ExplainError as exc:
            return _error(str(exc))
        findings = [explain(finding, generate) for finding in findings]

    report = build_report(args.file, len(events), findings)

    if out_path is not None:
        try:
            _save(out_path, to_json(report))
        except OSError as exc:
            return _error(f"cannot write report to {out_path}: {exc.strerror or exc}")
        print(f"nyyrikki: report saved to {out_path}", file=sys.stderr)

    sys.stdout.write(to_json(report) if args.json else to_text(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
