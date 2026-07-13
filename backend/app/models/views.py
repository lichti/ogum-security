from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

ViewScope = Literal["inventory", "findings", "compliance"]


class SavedView(BaseModel):
    """A saved combination of filters (+ visible columns) for a compound-filter screen."""

    key: str
    scope: ViewScope
    name: str
    filters: dict[str, Any] = Field(default_factory=dict)
    columns: list[str] | None = None
    owner: str
    is_system: bool = False
    pinned: bool = False
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class SavedViewCreateRequest(BaseModel):
    scope: ViewScope
    name: str
    filters: dict[str, Any] = Field(default_factory=dict)
    columns: list[str] | None = None


class SavedViewUpdateRequest(BaseModel):
    name: str | None = None
    filters: dict[str, Any] | None = None
    columns: list[str] | None = None
    pinned: bool | None = None
