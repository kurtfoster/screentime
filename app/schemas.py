"""Request and response models for the JSON API. Unknown fields are rejected."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

_ID = r"^[a-z][a-z0-9_]{0,63}$"
_REQ = r"^[A-Za-z0-9_-]{8,40}$"


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SiblingAuth(_Body):
    child_id: str = Field(pattern=_ID)
    password: str = Field(min_length=1, max_length=256)


class StartRequest(_Body):
    device_id: str = Field(pattern=_ID)
    minutes: int = Field(gt=0, le=24 * 60)
    participants: list[SiblingAuth] = Field(default_factory=list, max_length=4)
    request_id: str | None = Field(default=None, pattern=_REQ)


class ExtendRequest(_Body):
    mode: Literal["eligible", "all"] = "eligible"


class AddParticipantRequest(_Body):
    child_id: str = Field(pattern=_ID)
    password: str = Field(min_length=1, max_length=256)


class GrantRequest(_Body):
    minutes: int = Field(gt=0, le=24 * 60)
    request_id: str | None = Field(default=None, pattern=_REQ)


class TvStartRequest(_Body):
    minutes: int | None = Field(default=None, gt=0, le=24 * 60)
    until_stopped: bool = False
    request_id: str | None = Field(default=None, pattern=_REQ)


class PushSubscribeRequest(_Body):
    endpoint: str = Field(max_length=1024)
    keys: dict[str, Any]


class PushUnsubscribeRequest(_Body):
    endpoint: str = Field(max_length=1024)
