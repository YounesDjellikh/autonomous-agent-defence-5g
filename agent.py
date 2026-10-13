"""The single-agent IDS loop: observe a telemetry window -> retrieve similar
known signatures (RAG) -> reason with a local LLM -> emit a validated, logged
structured Verdict. No mitigation here (that is Phase 4)."""
from __future__ import annotations
import json, datetime
from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage

import config
from schema import TelemetryWindow, Verdict
from rag import SignatureStore

SYSTEM = """You are an autonomous intrusion-detection analyst for a 5G standalone core \
network that runs two isolated slices over shared infrastructure:
- Industrial-IoT slice (SST 3, DNN iot): normal traffic is steady, LOW-rate sensor \
telemetry (tens to low-hundreds of packets/sec, small packets).
- Public-Internet slice (SST 1, DNN internet): normal traffic is bursty web/streaming \
(can be hundreds of pps, larger packets) — this is BENIGN.
- 5G core control plane (AMF): once UEs are attached, the steady-state NAS registration \
rate is ~0. Sustained registrations indicate a problem.

You classify ONE telemetry window into exactly one label:
- benign  : normal traffic for that slice/plane.
- flood   : VOLUMETRIC or SCAN-LIKE flooding — a UE emitting ABNORMAL user-plane traffic \
that saturates or probes its slice: EITHER a very high packet-rate to a target, OR a \
moderate rate FANNED OUT across many destinations/ports (a slow scan/flood that a simple \
rate threshold misses).
- attach  : an AMF ATTACH STORM — sustained NAS registration requests on the control plane.

Principles:
- Use the retrieved known signatures as evidence, but reason about the actual numbers.
- Be PRECISE. Bursty-but-normal Internet traffic is benign. Do NOT flag an attack unless \
the telemetry clearly warrants it — wrongly blocking a legitimate slice is a costly error.
- Volumetric floods show as extreme pps on the USER plane; attach storms show as elevated \
registration rate on the CONTROL plane. Match the signal to the right plane.
- A flood is NOT only about raw pps: a moderate packet rate fanned out across MANY \
destinations/ports is a scan-like flood, while a HIGH rate to a SINGLE known destination \
can be a legitimate bulk transfer. Reason about fan-out, protocol and slice context, not \
the rate alone.

Then recommend a containment action (executed later only under safety controls):
- benign  -> recommended_action = "none"
- flood / attach with strong evidence -> "block" (precise, targets only the offending UE)
- borderline / lower-impact -> "rate_limit" or "monitor"
Return a structured verdict with a short rationale citing the telemetry and evidence."""


class IdsAgent:
    """Modes (for ablations):
      use_rag=True/False    : retrieve evidence vs reason from the window alone
      blind_labels=True     : show retrieved evidence TEXT but withhold its labels
                              (tests whether the agent reasons vs copies the nearest label)
    """
    def __init__(self, model: str = config.AGENT_MODEL, audit: bool = True,
                 use_rag: bool = True, blind_labels: bool = False):
        self.model = model
        self.llm = ChatOllama(
            model=model, base_url=config.OLLAMA_BASE_URL,
            temperature=config.LLM_TEMPERATURE, reasoning=config.LLM_REASONING,
        ).with_structured_output(Verdict, include_raw=True)
        self.use_rag = use_rag
        self.blind_labels = blind_labels
        self.store = SignatureStore() if use_rag else None
        self.audit = audit
        if audit:
            config.AUDIT_DIR.mkdir(parents=True, exist_ok=True)

    def _prompt(self, w: TelemetryWindow, evidence: list[dict]) -> list:
        if not self.use_rag:
            ev_block = "RETRIEVED SIGNATURES: (retrieval disabled — reason from the window alone)\n"
        else:
            lines = []
            for i, e in enumerate(evidence):
                tag = "" if self.blind_labels else f"[{e['label']}] "
                lines.append(f"  {i+1}. {tag}(sim {e['similarity']}): {e['text']}")
            ev_block = ("RETRIEVED KNOWN SIGNATURES (nearest first"
                        + (", labels hidden" if self.blind_labels else "") + "):\n"
                        + ("\n".join(lines) or "  (none)") + "\n")
        human = (
            f"CURRENT TELEMETRY WINDOW ({w.plane} plane):\n  {w.describe()}\n"
            f"  raw: pps={w.pps}, bps={w.bps}, mean_len={w.mean_len}, "
            f"cp_reg_rate={w.cp_reg_rate}, slice={w.slice}, src={w.src_ip}\n\n"
            f"{ev_block}\n"
            f"Classify this window."
        )
        return [SystemMessage(content=SYSTEM), HumanMessage(content=human)]

    def classify(self, w: TelemetryWindow) -> tuple[Verdict, list[dict]]:
        evidence = self.store.retrieve(w) if self.use_rag else []
        verdict = self._invoke(self._prompt(w, evidence))
        if self.audit:
            self._log(w, evidence, verdict)
        return verdict, evidence

    def _invoke(self, prompt) -> Verdict:
        """Crash-guarded structured call: never let one bad response kill a run."""
        try:
            out = self.llm.invoke(prompt)            # {parsed, raw, parsing_error}
            v = out.get("parsed") if isinstance(out, dict) else out
            if v is None:
                raise ValueError(out.get("parsing_error") if isinstance(out, dict) else "no parse")
            return v
        except Exception as e:                        # noqa: BLE001
            return Verdict(label="benign", confidence=0.0,
                           rationale=f"PARSE_FAILURE: {str(e)[:120]}",
                           recommended_action="none")

    def _log(self, w: TelemetryWindow, evidence: list[dict], v: Verdict):
        rec = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "model": self.model, "temperature": config.LLM_TEMPERATURE,
            "use_rag": self.use_rag, "blind_labels": self.blind_labels,
            "window": w.model_dump(),
            "evidence": [{"label": e.get("label"), "similarity": e.get("similarity"),
                          "text": e.get("text")} for e in evidence],
            "verdict": v.model_dump(),
        }
        with open(config.AUDIT_LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")
