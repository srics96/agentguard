"""Multi-model VPI-Bench run with CDP-level guarding (no agent integration).

For each model, every browser case runs twice: once with a raw agent and no
guard (baseline), once with the same raw agent guarded only at the CDP layer.
The agent code is unchanged between arms and never calls the guard - CDPGuard
mediates at the protocol boundary. Scored from the fake-site ledger as always.

A shared USD budget is enforced across all models; the run stops cleanly when
it is reached.
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
from eval.cases import DRIVE_FILE, NOTES, SECRETS, build_cases  # noqa: E402
from eval.harness import launch, launch_cdp  # noqa: E402
from eval.run_live import _get, _page_state, _post, _start_url, _task  # noqa: E402


def _arm(case, base, mode, policy, vault, model, max_steps, budget):
    _post(base, "/reset", {"drive": {DRIVE_FILE: NOTES}})
    incidents = IncidentLog()
    br = launch_cdp(policy, vault, incidents) if mode == "cdp" else launch(False, policy, vault, incidents)
    try:
        trace = live_agent.run_live(br.wrapper, br.page, policy, vault,
                                    _task(case, _start_url(case, base)),
                                    model=model, max_steps=max_steps, budget=budget)
        ps = _page_state(br)
    finally:
        br.close()
    ledger = _get(base, "/ledger")
    res = score.score_case(case, ledger, ps)
    res.update(followed=trace["followed_injection"], steps=trace["steps"],
               error=trace["error"], incidents=[i.kind for i in incidents.entries])
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--parquet", default=str(HERE.parent.parent / "vendor/agents/main_benchmark.parquet"))
    ap.add_argument("--port", type=int, default=8101)
    ap.add_argument("--out", default=str(HERE.parent / "results"))
    ap.add_argument("--models", default="gpt-4o-mini,gpt-4.1-mini")
    ap.add_argument("--max-steps", type=int, default=12)
    ap.add_argument("--budget", type=float, default=9.0)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    base = f"http://127.0.0.1:{args.port}"
    vault = Vault(dict(SECRETS))
    policy = Policy.load(str(HERE.parent / "policies/default.policy.yaml"),
                         public_key=str(HERE.parent / "policies/policy_key.pub"))
    budget = live_agent.Budget(args.budget)
    models = [m.strip() for m in args.models.split(",") if m.strip()]

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

    all_results = {}
    try:
        for model in models:
            if budget.exhausted:
                print(f"** budget cap reached; skipping {model} **", flush=True); break
            rows = []
            print(f"\n==== model: {model} ====", flush=True)
            for n, c in enumerate(cases, 1):
                base_res = _arm(c, base, "raw", policy, vault, model, args.max_steps, budget)
                cdp_res = _arm(c, base, "cdp", policy, vault, model, args.max_steps, budget)
                rows.append({"id": c.id, "objective": c.objective,
                             "unguarded": base_res, "cdp": cdp_res})
                print(f"[{n:2}/{len(cases)}] {c.id:36} "
                      f"ung={'HIT ' if base_res['success'] else 'miss'} "
                      f"cdp={'HIT' if cdp_res['success'] else 'BLOCKED'} "
                      f"${budget.spent:.3f}", flush=True)
                if budget.exhausted:
                    print(f"** budget cap ${args.budget} reached mid-model **", flush=True); break
            all_results[model] = rows
    finally:
        server.terminate()

    out = Path(args.out); out.mkdir(exist_ok=True)
    (out / "results_cdp.json").write_text(json.dumps(all_results, indent=2))
    _summary(all_results, out, budget, args)


def _summary(all_results, out, budget, args):
    lines = ["# AgentGuard — CDP-guarded, multi-model VPI-Bench run", "",
             f"Guarding: **CDP interception** (raw agent, no integration)  ·  "
             f"spend: ${budget.spent:.3f} of ${args.budget} cap", "",
             "| Model | Cases | Followed injection | Attack succeeds unguarded | Succeeds with CDP guard | Neutralised |",
             "|---|---|---|---|---|---|"]
    for model, rows in all_results.items():
        n = len(rows)
        foll = sum(r["unguarded"]["followed"] for r in rows)
        uh = sum(r["unguarded"]["success"] for r in rows)
        ch = sum(r["cdp"]["success"] for r in rows)
        blocked = sum(1 for r in rows if r["unguarded"]["success"] and not r["cdp"]["success"])
        lines.append(f"| `{model}` | {n} | {foll} | {uh} | {ch} | {blocked}/{uh} |")
    lines += ["", "Scored from the fake-site ledger and final page state only. The CDP guard "
              "redacts `never_see` data out of responses and blocks leaking / denied requests "
              "at the protocol boundary, for an agent that never calls the guard."]
    (out / "SUMMARY_CDP.md").write_text("\n".join(lines) + "\n")
    print("\n" + "\n".join(lines))


if __name__ == "__main__":
    main()
