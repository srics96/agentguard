"""Run all 87 browser cases, each with and without the guard, and score them.

For every case:
  * reset the fake server, seeding the Drive with the user's notes;
  * launch a Chromium page wrapped by nothing (unguarded arm) then by the
    guard (guarded arm);
  * run the identical scripted attack;
  * read the server ledger and the final page state, and score.

A live-LLM VPI-Bench run can be layered on later (see README); it is not needed
to measure the guard, which is what this harness does. No model is called and
no OpenAI budget is spent here.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from agentguard.detect import Vault  # noqa: E402
from agentguard.incidents import IncidentLog  # noqa: E402
from agentguard.policy import Policy  # noqa: E402
from eval import attacker, score  # noqa: E402
from eval.cases import DRIVE_FILE, NOTES, SECRETS, build_cases  # noqa: E402
from eval.harness import launch  # noqa: E402


def _post(base, path, obj=None):
    data = json.dumps(obj or {}).encode()
    req = urllib.request.Request(base + path, data=data,
                                 headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=5).read())


def _get(base, path):
    return json.loads(urllib.request.urlopen(base + path, timeout=5).read())


def _page_state(browser):
    st = {}
    try:
        for k in ("submitted", "deleted", "edited", "sent"):
            st[k] = browser.page.get_attribute("body", f"data-{k}") == "1"
    except Exception:
        pass
    return st


def _run_arm(case, base_url, guarded, policy, vault):
    _post(base_url, "/reset", {"drive": {DRIVE_FILE: NOTES}})
    incidents = IncidentLog()
    br = launch(guarded, policy, vault, incidents)
    try:
        trace = attacker.run_attack(br.wrapper, case, base_url)
        page_state = _page_state(br)
    finally:
        br.close()
    ledger = _get(base_url, "/ledger")
    result = score.score_case(case, ledger, page_state)
    result.update(killed=trace["killed"], error=trace["error"],
                  incidents=[i.kind for i in incidents.entries],
                  ledger_events=[e["event"] for e in ledger])
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--parquet", default=str(HERE.parent.parent /
                    "vendor/agents/main_benchmark.parquet"))
    ap.add_argument("--port", type=int, default=8077)
    ap.add_argument("--out", default=str(HERE.parent / "results"))
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    base_url = f"http://127.0.0.1:{args.port}"
    vault = Vault({k: v for k, v in SECRETS.items()})
    policy = Policy.load(str(HERE.parent / "policies/default.policy.yaml"),
                         public_key=str(HERE.parent / "policies/policy_key.pub"))

    server = subprocess.Popen([sys.executable, str(HERE / "fakesites/server.py"),
                               str(args.port)], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            _get(base_url, "/ledger"); break
        except Exception:
            time.sleep(0.2)
    else:
        server.terminate(); raise SystemExit("fake server did not start")

    cases = build_cases(args.parquet)
    if args.limit:
        cases = cases[:args.limit]
    rows = []
    try:
        for n, c in enumerate(cases, 1):
            ung = _run_arm(c, base_url, False, policy, vault)
            grd = _run_arm(c, base_url, True, policy, vault)
            rows.append({"id": c.id, "platform": c.platform, "objective": c.objective,
                         "attacker_objective": c.attacker_objective,
                         "unguarded": ung, "guarded": grd})
            print(f"[{n:2}/{len(cases)}] {c.id:38} "
                  f"unguarded={'HIT ' if ung['success'] else 'miss'} "
                  f"guarded={'HIT ' if grd['success'] else 'BLOCKED'}"
                  f"{' (killed)' if grd['killed'] else ''}", flush=True)
    finally:
        server.terminate()

    out = Path(args.out); out.mkdir(exist_ok=True)
    (out / "results.json").write_text(json.dumps(rows, indent=2))
    _summary(rows, out)


def _summary(rows, out):
    n = len(rows)
    ung_hit = sum(r["unguarded"]["success"] for r in rows)
    grd_hit = sum(r["guarded"]["success"] for r in rows)
    blocked = sum(1 for r in rows if r["unguarded"]["success"] and not r["guarded"]["success"])
    killed = sum(r["guarded"]["killed"] for r in rows)
    lines = [
        "# AgentGuard VPI-Bench browser evaluation",
        "",
        f"Cases: {n}",
        f"Attacks that succeed unguarded:        {ung_hit}/{n}",
        f"Attacks still succeeding with guard:   {grd_hit}/{n}",
        f"Attacks neutralised by the guard:      {blocked}/{ung_hit}",
        f"Sessions killed by the guard:          {killed}/{n}",
        "",
        "## By objective",
    ]
    from collections import defaultdict
    agg = defaultdict(lambda: [0, 0, 0])  # ung_hit, grd_hit, total
    for r in rows:
        a = agg[r["objective"]]
        a[0] += r["unguarded"]["success"]; a[1] += r["guarded"]["success"]; a[2] += 1
    lines.append("| objective | total | unguarded hits | guarded hits | blocked |")
    lines.append("|---|---|---|---|---|")
    for k, (uh, gh, t) in sorted(agg.items()):
        lines.append(f"| {k} | {t} | {uh} | {gh} | {uh-gh} |")
    lines += ["", "## Cases still succeeding with the guard", ""]
    leftover = [r for r in rows if r["guarded"]["success"]]
    if leftover:
        for r in leftover:
            lines.append(f"- `{r['id']}` ({r['objective']}): {r['guarded']['reason']}")
    else:
        lines.append("_none_")
    (out / "SUMMARY.md").write_text("\n".join(lines) + "\n")
    print("\n" + "\n".join(lines))


if __name__ == "__main__":
    main()
