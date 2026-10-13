"""Safety envelope around the scoped tools (Phase 4 / O4).

Turns an agent Verdict into a containment action subject to FOUR controls:
  1. Scoped tools     — tools.py refuses targets outside the slice subnets.
  2. Action allow-list — only REGISTRY actions may run.
  3. Human-on-the-loop — high-impact actions need approval; the threshold is the
     `autonomy` knob = the effectiveness-vs-controllability variable for O5.
  4. Kill switch       — a file that freezes all autonomous action and flushes
     every rule the agent installed.
Every decision and action is appended to an immutable JSONL audit log.

autonomy levels:
  0  manual           every action needs approval
  1  human-on-loop    blocks need approval; rate-limits are autonomous (default)
  2  autonomous       all actions auto (still scoped + audited + kill-switchable)
"""
from __future__ import annotations
import json, datetime
from pathlib import Path

import config
import tools
from schema import TelemetryWindow, Verdict

KILL_SWITCH = config.REPO / "data" / "KILL_SWITCH"
ACTION_LOG = config.AUDIT_DIR / "actions.jsonl"
HIGH_IMPACT = {"block_ip", "block_slice"}

# verdict.recommended_action -> (tool name, kwargs-from-window)
ACTION_MAP = {
    "block":      "block_ip",
    "rate_limit": "rate_limit_ip",
    "monitor":    None,
    "none":       None,
}


def kill_engaged() -> bool:
    return KILL_SWITCH.exists()


def engage_kill_switch(reason: str = "manual") -> dict:
    KILL_SWITCH.parent.mkdir(parents=True, exist_ok=True)
    KILL_SWITCH.write_text(f"engaged {reason}\n")
    flushed = tools.flush_agent_rules()
    return {"kill_switch": "ENGAGED", "reason": reason, **flushed}


def release_kill_switch() -> dict:
    if KILL_SWITCH.exists():
        KILL_SWITCH.unlink()
    return {"kill_switch": "released"}


class MitigationController:
    def __init__(self, autonomy: int = 1, approver=None, audit: bool = True,
                 conf_threshold: float = 0.6):
        """approver(action, target, window, verdict) -> bool. Defaults to deny
        when an approval is required but no approver is wired (fail-safe).
        conf_threshold gates autonomous containment (part of the O5 knob)."""
        self.autonomy = autonomy
        self.approver = approver or (lambda *a, **k: False)
        self.audit = audit
        self.conf_threshold = conf_threshold
        config.AUDIT_DIR.mkdir(parents=True, exist_ok=True)

    def _decide_action(self, verdict: Verdict) -> str | None:
        """Containment POLICY: detection (label) and policy (action) are
        separated. An explicit agent recommendation is honoured; otherwise an
        attack verdict above the confidence gate triggers a precise block."""
        if verdict.recommended_action in ("block", "rate_limit"):
            return ACTION_MAP[verdict.recommended_action]
        if verdict.label in ("flood", "attach") and verdict.confidence >= self.conf_threshold:
            return "block_ip"
        return None

    def _needs_approval(self, tool_name: str) -> bool:
        if self.autonomy >= 2:
            return False
        if self.autonomy == 0:
            return True
        return tool_name in HIGH_IMPACT      # level 1: only high-impact

    def handle(self, window: TelemetryWindow, verdict: Verdict) -> dict:
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        rec = {"ts": ts, "src_ip": window.src_ip, "slice": window.slice,
               "label": verdict.label, "recommended_action": verdict.recommended_action,
               "autonomy": self.autonomy}

        # 1. kill switch
        if kill_engaged():
            rec.update(outcome="frozen", reason="kill switch engaged")
            return self._log(rec)

        # 2. containment policy decides the action (detection != policy)
        tool_name = self._decide_action(verdict)
        if tool_name is None:
            rec.update(outcome="no_action",
                       reason=f"label={verdict.label} conf={verdict.confidence} action={verdict.recommended_action}")
            return self._log(rec)

        # 3. allow-list
        if tool_name not in tools.REGISTRY:
            rec.update(outcome="refused", reason=f"{tool_name} not in allow-list")
            return self._log(rec)

        target = window.src_ip
        rec["tool"] = tool_name; rec["target"] = target

        # 4. human-on-the-loop
        if self._needs_approval(tool_name):
            approved = bool(self.approver(tool_name, target, window, verdict))
            rec["approval_required"] = True; rec["approved"] = approved
            if not approved:
                rec.update(outcome="denied", reason="human declined")
                return self._log(rec)
        else:
            rec["approval_required"] = False

        # 5. execute (scoped tool validates the target again)
        result = tools.REGISTRY[tool_name](target)
        rec.update(outcome="executed" if result.get("ok") else "tool_error", result=result)
        return self._log(rec)

    def _log(self, rec: dict) -> dict:
        if self.audit:
            with open(ACTION_LOG, "a") as f:
                f.write(json.dumps(rec) + "\n")
        return rec
