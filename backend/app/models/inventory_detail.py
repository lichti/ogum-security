from __future__ import annotations

from pydantic import BaseModel, Field


class NarrativeDeepLink(BaseModel):
    """A clickable chip below the narrative that jumps to the tab backing a mentioned number."""

    label: str
    tab: str
    subtab: str | None = None
    count: int


class ResourceNarrativeSummary(BaseModel):
    """Deterministic, data-driven narrative for the Overview sub-tab (US-14.02).

    `generated_by` is always "template" today — Ogum.AI/RAG (Epic 05) is not yet
    implemented, so there is no LLM path to fall back *from*. This response shape
    is what an LLM-backed version would also return, so wiring one in later is an
    additive change, not a rewrite.
    """

    resource_key: str
    narrative: str
    generated_by: str = "template"
    finding_counts: dict[str, int] = Field(default_factory=dict)
    attack_path_count: int = 0
    deep_links: list[NarrativeDeepLink] = Field(default_factory=list)


class BlastRadiusNode(BaseModel):
    id: str
    resource_type: str
    name: str
    hop: int


class BlastRadiusEdge(BaseModel):
    source: str
    target: str
    edge_type: str


class BlastRadiusResponse(BaseModel):
    resource_key: str
    nodes: list[BlastRadiusNode] = Field(default_factory=list)
    edges: list[BlastRadiusEdge] = Field(default_factory=list)
    grouped_counts: dict[str, int] = Field(default_factory=dict)
