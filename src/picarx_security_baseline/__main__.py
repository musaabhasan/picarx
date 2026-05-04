from __future__ import annotations

import argparse
from pathlib import Path

from .checks import run_checks
from .report import render_json, render_markdown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run read-only Raspberry Pi / PiCar-X security baseline checks."
    )
    parser.add_argument(
        "--root",
        default="/",
        help="Target filesystem root to inspect. Defaults to /.",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format.",
    )
    parser.add_argument(
        "--output",
        help="Optional output file path. Parent directories are created if needed.",
    )
    args = parser.parse_args(argv)

    findings = run_checks(Path(args.root))
    if args.format == "json":
        rendered = render_json(findings)
    else:
        rendered = render_markdown(findings)

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
