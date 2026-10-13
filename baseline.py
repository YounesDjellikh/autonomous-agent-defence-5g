"""Rule-based monitor — the 'blunt instrument' baseline the agent is compared
against (dissertation O5). Static thresholds on user-plane packet rate and
control-plane registration rate, with a blanket block on trigger.

Deliberately simple: this is what a traditional monitor does — it sees a spike
and reacts, with no notion of slice context, fan-out, protocol, or intent."""
from __future__ import annotations
from schema import TelemetryWindow, Verdict


class RuleBasedMonitor:
    """Threshold detector + blanket containment.

    pps_threshold      : user-plane packets/sec above which -> flood + block
    reg_threshold      : control-plane registrations/sec at/above which -> attach + block
    """
    def __init__(self, pps_threshold: float = 1000.0, reg_threshold: float = 2.0):
        self.pps_threshold = pps_threshold
        self.reg_threshold = reg_threshold

    def classify(self, w: TelemetryWindow) -> Verdict:
        if w.plane == "control":
            if w.cp_reg_rate >= self.reg_threshold:
                return Verdict(label="attach", confidence=1.0,
                               rationale=f"rule: cp_reg_rate {w.cp_reg_rate} >= {self.reg_threshold}",
                               recommended_action="block")
            return Verdict(label="benign", confidence=1.0,
                           rationale=f"rule: cp_reg_rate {w.cp_reg_rate} < {self.reg_threshold}",
                           recommended_action="none")
        # user plane
        if w.pps >= self.pps_threshold:
            return Verdict(label="flood", confidence=1.0,
                           rationale=f"rule: pps {w.pps:.0f} >= {self.pps_threshold:.0f}",
                           recommended_action="block")
        return Verdict(label="benign", confidence=1.0,
                       rationale=f"rule: pps {w.pps:.0f} < {self.pps_threshold:.0f}",
                       recommended_action="none")
