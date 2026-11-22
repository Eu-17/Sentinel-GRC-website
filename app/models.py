from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator


class Rule(BaseModel):
    id: str = Field(pattern=r"^[A-Z0-9][A-Z0-9-]{0,39}$")
    name: str = Field(min_length=1, max_length=120)
    filter: str = Field(min_length=1, max_length=1000)
    short: str = Field(default="", max_length=120)
    summary: str = Field(default="", max_length=500)
    severity: Literal["Low", "Medium", "High", "Critical"] = "Medium"
    protocol: str = Field(default="TCP", max_length=30)
    direction: Literal["ingress", "egress"] = "ingress"
    technique: str = Field(default="", max_length=30)
    technique_name: str = Field(default="", max_length=120)
    tactic: str = Field(default="", max_length=120)
    controls: list[tuple[str, str]] = Field(default_factory=list, max_length=10)
    likelihood: int = Field(default=3, ge=1, le=5)
    impact: int = Field(default=3, ge=1, le=5)
    penalty: float = Field(default=1, ge=1, le=5)
    review: str = Field(default="", max_length=500)
    playbook: list[str] = Field(default_factory=list, max_length=10)
    min_connections: int | None = Field(default=None, ge=2, le=10000)
    window_seconds: int | None = Field(default=None, ge=1, le=3600)

    @model_validator(mode="after")
    def validate_rule(self):
        if not self.name.strip() or not self.filter.strip() or "\0" in self.filter:
            raise ValueError("Enter a name and a valid display filter.")
        if (self.min_connections is None) != (self.window_seconds is None):
            raise ValueError("Specify both a minimum connection count and a time window.")
        return self


class Flow(BaseModel):
    frame: int
    time: float
    source: str
    destination: str
    protocol: str
    bytes: int


class Control(BaseModel):
    id: str
    name: str
    state: Literal["PASS", "FAIL"]
    evidence: str


class Risk(BaseModel):
    status: Literal["CONTROL_FAILURE_DETECTED", "COMPLIANT"]
    likelihood: int
    impact: int
    inherent: int
    baseline: float
    score: float
    controls: list[Control]
    review: str | None


class Brief(BaseModel):
    source: Literal["Rule-based", "Local Ollama"]
    soc: str
    grc: str


class Finding(BaseModel):
    id: str
    name: str
    severity: str
    technique: str
    technique_name: str
    tactic: str
    count: int
    flows: list[Flow]
    firewall: list[str]
    address_count: int
    playbook: list[str]
    risk: Risk
    brief: Brief


class ProtocolCount(BaseModel):
    name: str
    frames: int


class EndpointCount(BaseModel):
    address: str
    frames: int


class Observation(BaseModel):
    title: str
    detail: str
    frames: list[int]
    addresses: list[str]
    rule_ids: list[str]
    suggested_filter: str | None
    grc: str
    controls: list[tuple[str, str]]


class CaptureOverview(BaseModel):
    protocols: list[ProtocolCount]
    endpoints: list[EndpointCount]
    observations: list[Observation]


class SavedCapture(BaseModel):
    id: str
    name: str
    size: int
    uploaded_at: datetime


class Analysis(BaseModel):
    capture: str
    engine: Literal["TShark", "Fixture replay"]
    frames: int
    findings: list[Finding]
    overview: CaptureOverview | None = None
    saved_capture: SavedCapture | None = None
