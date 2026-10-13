"""Pydantic data contracts for the agent (input window + structured verdict)."""
from __future__ import annotations
from typing import Literal
from pydantic import BaseModel, Field


class TelemetryWindow(BaseModel):
    """One NetFlow-style telemetry window the agent reasons over (from netflow.py)."""
    scenario: str = ""
    window: int = 0
    plane: Literal["user", "control"] = "user"
    src_ip: str = ""
    slice: str = ""
    pkts: int = 0
    bytes: int = 0
    pps: float = 0.0
    bps: float = 0.0
    mean_len: float = 0.0
    uniq_dst: int = 0
    uniq_dport: int = 0
    n_udp: int = 0
    n_tcp: int = 0
    n_icmp: int = 0
    cp_reg_reqs: int = 0
    cp_reg_rate: float = 0.0

    def describe(self) -> str:
        """Natural-language summary used for embedding + the reasoning prompt."""
        if self.plane == "control":
            return (f"5G core control-plane window. NAS registration requests: "
                    f"{self.cp_reg_reqs} ({self.cp_reg_rate}/s). "
                    f"(Steady-state normal is ~0 registrations once UEs are attached.)")
        return (f"{self.slice} slice user-plane flow from {self.src_ip}. "
                f"Rate {self.pps:.0f} pps / {self.bps:.0f} bps, mean packet {self.mean_len:.0f} B. "
                f"Protocols: {self.n_udp} UDP, {self.n_tcp} TCP, {self.n_icmp} ICMP. "
                f"Fan-out: {self.uniq_dst} dst IPs, {self.uniq_dport} dst ports.")


class Verdict(BaseModel):
    """The agent's structured decision for a window (validated => excessive-agency guard)."""
    label: Literal["benign", "flood", "attach"] = Field(
        description="benign | flood (volumetric) | attach (AMF registration storm)")
    confidence: float = Field(ge=0.0, le=1.0,
        description="0..1 confidence in the label")
    rationale: str = Field(
        description="one or two sentences citing the telemetry + retrieved evidence")
    recommended_action: Literal["none", "monitor", "rate_limit", "block"] = Field(
        default="none",
        description="containment recommendation (executed only in Phase 4, under safety controls)")
