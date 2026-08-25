from __future__ import annotations

from pydantic import BaseModel, Field


class NarrativeStep(BaseModel):
    index: int
    total: int
    title: str
    text: str


class PathNarrativeSummary(BaseModel):
    """Deterministic, data-driven narrative for the Path Info panel (US-14.13).

    `generated_by` mirrors ResourceNarrativeSummary's contract
    (inventory_detail.py) — Ogum.AI/RAG (Epic 05) is still not implemented,
    so this is the template fallback path a future LLM-backed narrative would
    replace additively, not the LLM path itself.
    """

    path_id: str
    steps: list[NarrativeStep] = Field(default_factory=list)
    generated_by: str = "template"
