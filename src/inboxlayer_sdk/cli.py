"""CLI utilities for developer workflows."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from inboxlayer_sdk.contracts import SDK_ENDPOINT_COVERAGE


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}


def _load_openapi(path: Path) -> set[str]:
    payload = json.loads(path.read_text())
    paths = payload.get("paths", {})
    discovered: set[str] = set()
    for path, operations in paths.items():
        for method in operations:
            if not isinstance(method, str) or method.lower() not in HTTP_METHODS:
                continue
            discovered.add(f"{method.upper()} {path}")
    return discovered


def _diff_contracts(discovered: set[str], contract: dict[str, str]) -> tuple[list[str], list[str]]:
    expected = set(contract)
    missing = sorted(expected - discovered)
    extra = sorted(discovered - expected)
    return missing, extra


def _main() -> int:
    openapi_default = Path(__file__).resolve().parent / "openapi" / "api-v1.json"
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--openapi",
        default=(
            openapi_default
            if openapi_default.exists()
            else Path(__file__).resolve().parent.parent.parent / "docs" / "openapi" / "api-v1.json"
        ),
        type=Path,
    )
    args = parser.parse_args()

    discovered = _load_openapi(args.openapi)
    missing, extra = _diff_contracts(discovered, SDK_ENDPOINT_COVERAGE)

    if missing:
        print("Missing endpoints in OpenAPI for covered SDK methods:")
        for endpoint in missing:
            method = SDK_ENDPOINT_COVERAGE[endpoint]
            print(f"  - {endpoint} ({method})")

    if extra:
        print("OpenAPI endpoints not represented in SDK coverage map:")
        for endpoint in extra:
            print(f"  - {endpoint}")

    if missing or extra:
        print("Contract coverage check failed")
        return 1

    print("Contract coverage check passed")
    return 0


def main() -> None:
    raise SystemExit(_main())
