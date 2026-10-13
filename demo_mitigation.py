#!/usr/bin/env python3
"""Phase 4 live demo: the agent detects a flood and CONTAINS it precisely, while
the co-resident benign UEs keep working — the precision a blanket rule destroys.

Flow: start a flood from UE3 (IoT slice) -> measure a live telemetry window ->
agent classifies -> MitigationController blocks ONLY UE3 (under human-on-the-loop
+ audit + kill switch) -> verify UE1 (same slice) and UE2 (other slice) still
reach their gateways. Then show what the rule baseline would do (blanket-block the
whole IoT slice, taking UE1 down too).

Run as root in the venv:  python agent/demo_mitigation.py
"""
import sys, time, subprocess, argparse
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

import config, tools
from schema import TelemetryWindow
from agent import IdsAgent
from mitigation import MitigationController, release_kill_switch, engage_kill_switch

REPO = config.REPO


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)


def ns_of(sub):
    out = sh("ip netns list").stdout
    for line in out.splitlines():
        if sub in line:
            return line.split()[0]
    return ""


def ue_ip(ns):
    out = sh(f"ip netns exec {ns} ip -br -4 addr show").stdout
    for line in out.splitlines():
        if "uesimtun" in line:
            return line.split()[2].split("/")[0]
    return ""


def gw(ip):
    return ".".join(ip.split(".")[:3]) + ".1"


def reachable(ns, ip):
    return sh(f"ip netns exec {ns} ping -c1 -W2 {gw(ip)}").returncode == 0


def measure_window(attacker_ip, secs=3):
    """Capture ogstun briefly and build the attacker's user-plane window."""
    sh(f"timeout {secs+1} tshark -i ogstun -a duration:{secs} -w /tmp/demo.pcap -q")
    out = sh(f"tshark -r /tmp/demo.pcap -Y 'ip.src=={attacker_ip}' "
             f"-T fields -e ip.dst -e udp.dstport -e frame.len").stdout.strip().splitlines()
    pkts = len(out)
    dsts, ports, length = set(), set(), 0
    for line in out:
        f = line.split("\t")
        if f and f[0]:
            dsts.add(f[0])
        if len(f) > 1 and f[1]:
            ports.add(f[1])
        if len(f) > 2 and f[2].isdigit():
            length += int(f[2])
    return TelemetryWindow(
        scenario="live", plane="user", src_ip=attacker_ip, slice="iot",
        pkts=pkts, bytes=length, pps=round(pkts/secs, 1),
        bps=round(length*8/secs, 0), mean_len=round(length/pkts, 1) if pkts else 0,
        uniq_dst=len(dsts), uniq_dport=len(ports), n_udp=pkts,
    )


def banner(t):
    print("\n" + "="*64 + f"\n {t}\n" + "="*64)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--autonomy", type=int, default=1, help="0 manual, 1 human-on-loop, 2 auto")
    ap.add_argument("--approve", action="store_true", help="auto-approve (demo)")
    a = ap.parse_args()

    # clean slate
    release_kill_switch()
    tools.flush_agent_rules()

    ns1, ns2, ns3 = ns_of("001-iot"), ns_of("internet"), ns_of("099-iot")
    if not (ns1 and ns2 and ns3):
        print("Testbed not up. Run: bash telemetry/ensure_testbed.sh"); sys.exit(1)
    ip1, ip2, ip3 = ue_ip(ns1), ue_ip(ns2), ue_ip(ns3)
    print(f"UE1 benign-iot={ip1}  UE2 benign-internet={ip2}  UE3 ATTACKER-iot={ip3}")

    banner("1. Baseline — all UEs healthy")
    for n, ip, lbl in ((ns1, ip1, "UE1 iot"), (ns2, ip2, "UE2 internet"), (ns3, ip3, "UE3 iot")):
        print(f"   {lbl:<14} {ip} -> gateway: {'OK' if reachable(n, ip) else 'FAIL'}")

    banner("2. UE3 launches a volumetric flood on the IoT slice")
    flood = subprocess.Popen(
        f"ip netns exec {ns3} python3 telemetry/traffic/gen.py --dst-base 10.46.0 "
        f"--dst-count 1 --pps 20000 --size 250 --duration 30", shell=True, cwd=REPO,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t_attack = time.time()
    time.sleep(1)

    banner("3. Agent observes a live telemetry window and decides")
    w = measure_window(ip3, secs=3)
    print(f"   measured: src={w.src_ip} pps={w.pps} uniq_dst={w.uniq_dst} bps={w.bps:.0f}")
    agent = IdsAgent(audit=True)
    verdict, _ = agent.classify(w)
    t_detect = time.time()
    print(f"   VERDICT: {verdict.label}  action={verdict.recommended_action}  conf={verdict.confidence}")
    print(f"   rationale: {verdict.rationale[:160]}")

    banner("4. Mitigation under the safety envelope (autonomy="+str(a.autonomy)+")")
    approver = (lambda *x, **k: True) if a.approve else None
    ctrl = MitigationController(autonomy=a.autonomy, approver=approver)
    result = ctrl.handle(w, verdict)
    t_contain = time.time()
    print(f"   {result.get('outcome')}: {result.get('tool')} {result.get('target','')} "
          f"approved={result.get('approved','n/a')}")
    if result.get("result"):
        print(f"   tool: {result['result']}")

    time.sleep(2)
    banner("5. Verify PRECISION — only the attacker is contained")
    r3 = reachable(ns3, ip3); r1 = reachable(ns1, ip1); r2 = reachable(ns2, ip2)
    print(f"   UE3 ATTACKER  {ip3} -> {'STILL UP (containment failed)' if r3 else 'CONTAINED ✓'}")
    print(f"   UE1 benign    {ip1} -> {'STILL UP ✓' if r1 else 'COLLATERAL DOWN ✗'}  (same IoT slice)")
    print(f"   UE2 benign    {ip2} -> {'STILL UP ✓' if r2 else 'COLLATERAL DOWN ✗'}  (other slice)")
    print(f"\n   MTTD ~{t_detect-t_attack:.1f}s   MTTC ~{t_contain-t_attack:.1f}s")

    banner("6. Contrast: what the RULE baseline does — blanket-block the IoT slice")
    print("   rule action = block_slice('iot')  (10.46.0.0/16)")
    print("   -> would also drop UE1 (10.46.x) — collateral damage the agent avoids.")
    print("   (not executed; shown for comparison)")

    banner("7. Kill switch — operator freezes + flushes everything")
    ks = engage_kill_switch("demo")
    print(f"   {ks}")
    r3b = reachable(ns3, ip3)
    print(f"   UE3 after flush -> {'restored (rules cleared)' if r3b else 'still blocked'}")
    release_kill_switch()

    flood.terminate()
    tools.flush_agent_rules()
    print("\nAudit: data/audit/actions.jsonl   |   decisions: data/audit/decisions.jsonl")
    print("DEMO_DONE")


if __name__ == "__main__":
    main()
