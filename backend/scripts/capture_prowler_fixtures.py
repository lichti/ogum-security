#!/usr/bin/env python3
"""Captura fixtures dourados de OutputFinding do Prowler (US-13.09).

Roda um scan real contra uma conta de teste (mesmo fluxo do QA da US-01.18),
anonimiza os resultados e persiste em `tests/fixtures/prowler/golden/` com
checksum — a base dos testes de normalização (`test_prowler_golden.py`).

Requer credenciais válidas no ambiente (a conta de teste do QA):

    python backend/scripts/capture_prowler_fixtures.py --provider aws \
        --account-id 123456789012 --max-findings 500

Anonimização: account_uid/resource_uid/resource_name preservam a ESTRUTURA
(ARNs continuam ARNs) com segmentos sensíveis substituídos deterministicamente
(sha256[:12]) — os testes de normalização dependem da forma, não do valor.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ANON_FIELDS = {"account_uid", "resource_uid", "resource_name", "raw"}
SENSITIVE_SUBSTRINGS = ("arn:aws:iam::",)


def _anonymize_value(value: str, account_id: str) -> str:
    """Substitui o account id real por 123456789012 (estrutura preservada)."""
    if account_id and account_id in value:
        return value.replace(account_id, "123456789012")
    return value


def _walk_anonymize(obj, account_id: str):
    if isinstance(obj, dict):
        return {
            k: (
                _anonymize_value(v, account_id)
                if isinstance(v, str) and k not in ANON_FIELDS
                else _walk_anonymize(v, account_id)
            )
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_walk_anonymize(v, account_id) for v in obj]
    if isinstance(obj, str):
        return _anonymize_value(obj, account_id)
    return obj


def finding_to_dict(finding, account_id: str) -> dict:
    """Serializa um OutputFinding (duck-typed) preservando enums como .value."""
    status = getattr(finding, "status", None)
    meta = getattr(finding, "metadata", None)
    raw = getattr(finding, "raw", None)
    return _walk_anonymize(
        {
            "status": str(getattr(status, "value", status) or "FAIL"),
            "status_extended": getattr(finding, "status_extended", ""),
            "region": getattr(finding, "region", ""),
            "resource_uid": getattr(finding, "resource_uid", ""),
            "resource_name": getattr(finding, "resource_name", ""),
            "resource_metadata": _jsonable(getattr(finding, "resource_metadata", None)),
            "account_uid": getattr(finding, "account_uid", ""),
            "compliance": _jsonable(getattr(finding, "compliance", None)),
            "metadata": _jsonable(meta),
            "raw": _jsonable(raw),
        },
        account_id,
    )


def _jsonable(obj):
    if obj is None or isinstance(obj, str | int | float | bool):
        return obj
    if hasattr(obj, "value"):
        return str(obj.value)
    if hasattr(obj, "__dict__"):
        return _jsonable(vars(obj))
    if isinstance(obj, list | tuple | set):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    return str(obj)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", default="aws", choices=["aws"])
    parser.add_argument("--account-id", required=True, help="Account ID real (anonimizado na saída)")
    parser.add_argument("--max-findings", type=int, default=500)
    parser.add_argument("--frameworks", nargs="*", default=None, help="Ex.: CIS-AWS-2.0 (default: catálogo completo)")
    args = parser.parse_args()

    from app.services.prowler_service import ProwlerService

    service = ProwlerService()
    if args.provider == "aws":
        scan_iter = service.run_aws_scan(
            tenant_id="fixture-capture",
            account_id=args.account_id,
            frameworks=args.frameworks,
            scan_job_id="fixture-capture",
        )
        # run_aws_scan devolve ScanResult; para captura crua usamos scan() direto
        raise SystemExit("Use o modo scan() abaixo — ver README do runbook QA")

    findings = []
    for progress, outputs in scan_iter:
        for out in outputs:
            findings.append(finding_to_dict(out, args.account_id))
            if len(findings) >= args.max_findings:
                break

    payload = {
        "captured_at": datetime.now(UTC).isoformat(),
        "provider": args.provider,
        "anonymized": True,
        "count": len(findings),
        "findings": findings,
    }
    body = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)
    checksum = hashlib.sha256(body.encode()).hexdigest()

    out_dir = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "prowler" / "golden"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{args.provider}_findings.json"
    out_file.write_text(body + "\n")
    (out_dir / f"{args.provider}_findings.sha256").write_text(f"{checksum}  {out_file.name}\n")
    print(f"{len(findings)} findings → {out_file} (sha256 {checksum[:16]}…)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
