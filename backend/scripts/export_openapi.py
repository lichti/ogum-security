#!/usr/bin/env python3
"""
Export the FastAPI app's OpenAPI schema.

This does not require ArangoDB, Redis, or any other service to be running —
app.openapi() is pure introspection over the route definitions, and every
Settings field has a default (see app/core/config.py), so importing the app
never touches the network.

Writes to stdout by default so it works the same way whether run locally via
Poetry (cwd = repo root or backend/) or inside the backend container (which
only has backend/ bind-mounted, not the repo root where docs/ lives):

    # Regenerate docs/api/openapi.json from the repo root
    python backend/scripts/export_openapi.py > docs/api/openapi.json

    # From inside the backend container (docs/ isn't mounted there)
    docker compose exec -T backend python scripts/export_openapi.py > docs/api/openapi.json

    # CI drift check — fails if the committed file doesn't match the code
    python backend/scripts/export_openapi.py --check docs/api/openapi.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Allow running from repo root or from backend/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.main import app  # noqa: E402


def _rendered_schema() -> str:
    schema = app.openapi()
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--check",
        metavar="PATH",
        help="Don't print anything — exit 1 if PATH differs from the current schema.",
    )
    args = parser.parse_args()

    rendered = _rendered_schema()

    if args.check:
        path = Path(args.check)
        current = path.read_text() if path.exists() else ""
        if current != rendered:
            print(f"{path} is out of date — regenerate it and commit the change:", file=sys.stderr)
            print(f"  python backend/scripts/export_openapi.py > {path}", file=sys.stderr)
            return 1
        print(f"{path} is up to date.", file=sys.stderr)
        return 0

    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
