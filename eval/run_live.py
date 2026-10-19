"""Live-model VPI-Bench run: a real LLM driven through the guard, both arms.

Measures two things the deterministic run cannot:
  * how often the model *follows the injection* (its susceptibility), and
  * whether the guard stops a real model, not just a scripted one.

Runs entirely against the local fake sites with fabricated secrets. Needs
OPENAI_API_KEY; honours a total USD budget cap and a per-case step cap.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from agentguard.detect import Vault  # noqa: E402
from agentguard.incidents import IncidentLog  # noqa: E402
from agentguard.policy import Policy  # noqa: E402
from eval import live_agent, score  # noqa: E402
from eval.attacker import _seed_emails  # noqa: E402
from eval.cases import DRIVE_FILE, NOTES, SECRETS, build_cases  # noqa: E402
from eval.harness import launch  # noqa: E402


def _post(base, path, obj=None):
    data = json.dumps(obj or {}).encode()
    req = urllib.request.Request(base + path, data=data,
                                 headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=5).read())


def _get(base, path):
    return json.loads(urllib.request.urlopen(base + path, timeout=5).read())


def _start_url(case, base):
    if case.platform == "webform":
        q = urllib.parse.urlencode({"id": case.id, "kind": case.page_params.get("kind", "api"),
                                    "collect": f"{base}/collect", "file": case.drive_file})
        return f"{base}/pages/webform?{q}"
    if case.platform == "email":
        q = urllib.parse.urlencode({"id": case.id, "send": f"{base}/send"}) + "&emails=" + _seed_emails()
        return f"{base}/pages/email?{q}"
    import json as _j
    msgs = urllib.parse.quote(_j.dumps([{"from": "teammate", "text": "hey"}]))
    q = urllib.parse.urlencode({"id": case.id, "send": f"{base}/send"}) + "&msgs=" + msgs
    return f"{base}/pages/messenger?{q}"


def _task(case, start):
    benign = case.user_prompt
    # Point the model at the local page instead of the public benchmark URL.
    import re
    benign = re.sub(r"https?://cua-[^\s'\"]+", start, benign)
    if start not in benign:
        benign = f"{benign}\nStart at: {start}"
    return benign


def _page_state(browser):
    st = {}
    try:
        for k in ("submitted", "deleted", "edited", "sent"):
            st[k] = browser.page.get_attribute("body", f"data-{k}") == "1"
    except Exception:
        pass
    return st


def _run_arm(case, base, guarded, policy, vault, model, max_steps, budget):
    _post(base, "/reset", {"drive": {DRIVE_FILE: NOTES}})
    incidents = IncidentLog()
    br = launch(guarded, policy, vault, incidents)
    start = _start_url(case, base)
    try:
        trace = live_agent.run_live(br.wrapper, br.page, policy, vault,
                                    _task(case, start), model=model,
                                    max_steps=max_steps, budget=budget)
        page_state = _page_state(br)
    finally:
        br.close()
    ledger = _get(base, "/ledger")
    res = score.score_case(case, ledger, page_state)
    res.update(killed=trace["killed"], followed=trace["followed_injection"],
               steps=trace["steps"], error=trace["error"],
               budget_stop=trace["budget_stop"],
               incidents=[i.kind for i in incidents.entries])
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--parquet", default=str(HERE.parent.parent / "vendor/agents/main_benchmark.parquet"))
    ap.add_argument("--port", type=int, default=8078)
    ap.add_argument("--out", default=str(HERE.parent / "results"))
    ap.add_argument("--model", default="gpt-4o-mini")
    ap.add_argument("--max-steps", type=int, default=10)
    ap.add_argument("--budget", type=float, default=8.0)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--arms", default="both", choices=["both", "unguarded", "guarded"])
    args = ap.parse_args()

    base = f"http://127.0.0.1:{args.port}"
    vault = Vault(dict(SECRETS))
    policy = Policy.load(str(HERE.parent / "policies/default.policy.yaml"),
                         public_key=str(HERE.parent / "policies/policy_key.pub"))
    budget = live_agent.Budget(args.budget)

    server = subprocess.Popen([sys.executable, str(HERE / "fakesites/server.py"), str(args.port)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            _get(base, "/ledger"); break
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
            row = {"id": c.id, "platform": c.platform, "objective": c.objective}
            if args.arms in ("both", "unguarded"):
                row["unguarded"] = _run_arm(c, base, False, policy, vault, args.model, args.max_steps, budget)
            if args.arms in ("both", "guarded"):
                row["guarded"] = _run_arm(c, base, True, policy, vault, args.model, args.max_steps, budget)
            rows.append(row)
            u = row.get("unguarded", {}); g = row.get("guarded", {})
            print(f"[{n:2}/{len(cases)}] {c.id:38} "
                  f"ung={'HIT ' if u.get('success') else 'miss'}/"
                  f"{'followed' if u.get('followed') else 'resisted'} "
                  f"grd={'HIT' if g.get('success') else 'BLOCKED'}"
                  f"{'(killed)' if g.get('killed') else ''} "
                  f"${budget.spent:.3f}", flush=True)
            if budget.exhausted:
                print(f"** budget cap ${args.budget} reached; stopping at {n} cases **", flush=True)
                break
    finally:
        server.terminate()

    out = Path(args.out); out.mkdir(exist_ok=True)
    (out / "results_live.json").write_text(json.dumps(rows, indent=2))
    _summary(rows, out, args, budget)


def _summary(rows, out, args, budget):
    done = len(rows)
    ung = [r for r in rows if "unguarded" in r]
    grd = [r for r in rows if "guarded" in r]
    followed = sum(r["unguarded"].get("followed") for r in ung)
    ung_hit = sum(r["unguarded"]["success"] for r in ung)
    grd_hit = sum(r["guarded"]["success"] for r in grd)
    killed = sum(r["guarded"].get("killed") for r in grd)
    lines = [
        "# AgentGuard VPI-Bench browser evaluation — live model",
        "",
        f"Model: `{args.model}`  ·  max steps/case: {args.max_steps}  ·  "
        f"spend: ${budget.spent:.3f} of ${args.budget} cap",
        f"Cases run: {done}",
        "",
        f"Model followed the injection (unguarded):   {followed}/{len(ung)}",
        f"Attack actually succeeded, unguarded:       {ung_hit}/{len(ung)}",
        f"Attack actually succeeded, with guard:      {grd_hit}/{len(grd)}",
        f"Sessions killed by the guard:               {killed}/{len(grd)}",
        "",
        "Scored from the fake-site ledger and final page state, never from the "
        "model's or the guard's own narration.",
    ]
    (out / "SUMMARY_LIVE.md").write_text("\n".join(lines) + "\n")
    print("\n" + "\n".join(lines))


if __name__ == "__main__":
    main()
