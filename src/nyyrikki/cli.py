"""Command-line interface: nyyrikki scan FILE."""

from __future__ import annotations

import argparse
import json
import sys

from nyyrikki import __version__
from nyyrikki.events import ParseError, load_events
from nyyrikki.explain import DEFAULT_OLLAMA_URL, ExplainError, explain, ollama_generator
from nyyrikki.rules import run_rules


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nyyrikki",
        description="Identify potentially suspicious activity in exported Windows Security events.",
    )
    parser.add_argument("--version", action="version", version=f"nyyrikki {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan an event XML file and print findings as JSON")
    scan.add_argument("file", help="event XML exported with wevtutil or Event Viewer")
    scan.add_argument("--explain", action="store_true", help="ask a local model to explain each finding")
    scan.add_argument("--model", help="local Ollama model name (required with --explain)")
    scan.add_argument("--ollama-url", default=DEFAULT_OLLAMA_URL, help="local Ollama URL (localhost only)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.explain and not args.model:
        parser.error("--explain requires --model")

    try:
        events = load_events(args.file)
    except ParseError as exc:
        print(f"nyyrikki: {exc}", file=sys.stderr)
        return 2

    findings = run_rules(events)

    if args.explain:
        try:
            generate = ollama_generator(args.model, args.ollama_url)
        except ExplainError as exc:
            print(f"nyyrikki: {exc}", file=sys.stderr)
            return 2
        findings = [explain(finding, generate) for finding in findings]

    report = {
        "agent": "nyyrikki",
        "version": __version__,
        "source": args.file,
        "events_parsed": len(events),
        "findings": [finding.to_dict() for finding in findings],
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
