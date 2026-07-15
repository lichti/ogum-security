"""
Deterministic, paginated narrative for an attack path (US-14.13).

Same template-only approach as inventory_detail_service.py::_build_narrative
(Epic 14 Sprint 2) — Ogum.AI/RAG (Epic 05) does not exist yet, so there is no
LLM path to generate this from. Four fixed steps built from data already on
the enriched path doc and its associated findings.
"""

from __future__ import annotations

from typing import Any

from app.models.attack_path_narrative import NarrativeStep, PathNarrativeSummary

_EXPOSURE_TEXT: dict[str, str] = {
    "internet_facing": "directly reachable from the public internet",
    "public_facing": "publicly accessible",
    "trusted_access": "reachable only through an already-trusted identity, with no direct network exposure",
    "none": "not exposed through any signal currently tracked in the graph",
}

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")


def _entry_point_step(path_doc: dict[str, Any]) -> NarrativeStep:
    entry_name = path_doc.get("entry_point_name") or "an unnamed resource"
    entry_type = (path_doc.get("entry_point_type") or "resource").replace("_", " ")
    exposure = path_doc.get("exposure") or "none"
    exposure_text = _EXPOSURE_TEXT.get(exposure, _EXPOSURE_TEXT["none"])
    text = f"The path starts at {entry_name}, a {entry_type} that is {exposure_text}."
    return NarrativeStep(index=1, total=4, title="Entry Point", text=text)


def _path_pivot_step(path_doc: dict[str, Any]) -> NarrativeStep:
    hops = int(path_doc.get("hops", 0))
    hop_word = "hop" if hops == 1 else "hops"
    rule = path_doc.get("rule", "unknown")
    sentences = [f'From there, it reaches the target in {hops} {hop_word} via the "{rule}" detection rule.']

    if path_doc.get("is_cross_account"):
        account_ids = path_doc.get("account_ids") or []
        sentences.append(f"The path crosses {len(account_ids)} distinct cloud accounts.")
    if path_doc.get("is_cross_cloud_provider"):
        sentences.append("It also crosses more than one cloud provider.")

    mitre_chain = path_doc.get("mitre_chain") or []
    if mitre_chain:
        sentences.append(f"It maps to {len(mitre_chain)} MITRE ATT&CK technique(s) in sequence.")

    return NarrativeStep(index=2, total=4, title="Path & Pivot", text=" ".join(sentences))


def _target_impact_step(path_doc: dict[str, Any]) -> NarrativeStep:
    target_name = path_doc.get("target_name") or "an unnamed resource"
    target_type = (path_doc.get("target_type") or "resource").replace("_", " ")
    sentences = [f"The target is {target_name}, a {target_type}."]

    reason = path_doc.get("target_crown_jewel_reason")
    if reason:
        reason_text = {
            "internet_facing": "it is internet-facing",
            "stores_sensitive_data": "it stores sensitive data",
            "high_privilege_identity": "it holds high-privilege access",
            "manually_flagged": "it was manually flagged as high-value",
        }.get(reason, "it was flagged as high-value")
        sentences.append(f"It is marked as a crown jewel because {reason_text}.")

    if path_doc.get("is_toxic_combination"):
        sentences.append(
            "This path is classified as a toxic combination — the compounded risk "
            "is higher than either misconfiguration alone."
        )

    return NarrativeStep(index=3, total=4, title="Target & Impact", text=" ".join(sentences))


def _findings_evidence_step(findings: list[dict[str, Any]]) -> NarrativeStep:
    if not findings:
        return NarrativeStep(
            index=4,
            total=4,
            title="Findings & Evidence",
            text="No open findings are currently linked to the resources along this path.",
        )

    counts: dict[str, int] = {}
    for f in findings:
        sev = (f.get("severity") or "").upper()
        counts[sev] = counts.get(sev, 0) + 1

    breakdown = ", ".join(f"{counts[sev]} {sev.lower()}" for sev in _SEVERITIES if counts.get(sev))
    total = len(findings)
    plural = "s" if total != 1 else ""
    text = f"{total} open finding{plural} support this path ({breakdown})."
    return NarrativeStep(index=4, total=4, title="Findings & Evidence", text=text)


def build_path_narrative(
    path_doc: dict[str, Any],
    findings: list[dict[str, Any]],
) -> PathNarrativeSummary:
    steps = [
        _entry_point_step(path_doc),
        _path_pivot_step(path_doc),
        _target_impact_step(path_doc),
        _findings_evidence_step(findings),
    ]
    return PathNarrativeSummary(path_id=path_doc.get("path_id", path_doc.get("_key", "")), steps=steps)
