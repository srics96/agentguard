"""Guarded browser-agent service — the thing you deploy and talk to.

A small HTTP API. You POST a task; the service runs an LLM browser agent that
drives a headless Chromium **through AgentGuard** (in-process GuardedBrowser, so
reads are redacted and leaks/denied actions are blocked), and returns the
agent's answer plus every guard incident. No request can make the agent
exfiltrate a protected value or take a denied action.

Env:
  OPENAI_API_KEY   required — the model the agent runs on
  AGENTGUARD_MODEL default gpt-4.1-mini
  AGENTGUARD_SECRETS   optional JSON {"name":"value"} of the user's secrets to protect
  AGENTGUARD_MAX_STEPS default 15
  AGENTGUARD_BUDGET_USD default 0.50 per task
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel

from agentguard.detect import Vault
from agentguard.incidents import IncidentLog
from agentguard.policy import Policy
from eval import live_agent
from eval.harness import launch

ROOT = Path(__file__).resolve().parent.parent
app = FastAPI(title="Guarded Browser Agent", version="0.1.0")
_lock = threading.Lock()   # one browser/task at a time (small instance)

POLICY = Policy.load(str(ROOT / "policies/default.policy.yaml"),
                     public_key=str(ROOT / "policies/policy_key.pub"))
SECRETS = json.loads(os.environ.get("AGENTGUARD_SECRETS", "{}"))
MODEL = os.environ.get("AGENTGUARD_MODEL", "gpt-4.1-mini")
MAX_STEPS = int(os.environ.get("AGENTGUARD_MAX_STEPS", "15"))
BUDGET = float(os.environ.get("AGENTGUARD_BUDGET_USD", "0.50"))


class Task(BaseModel):
    goal: str
    start_url: str | None = None


@app.get("/health")
def health():
    return {"ok": True, "model": MODEL, "protected_values": len(SECRETS)}


@app.post("/task")
def run_task(task: Task):
    """Run one guarded agent task. Serialized; returns answer + guard incidents."""
    prompt = task.goal
    if task.start_url:
        prompt = f"{prompt}\nStart at: {task.start_url}"
    with _lock:
        incidents = IncidentLog()
        vault = Vault(dict(SECRETS))
        br = launch(True, POLICY, vault, incidents)
        try:
            trace = live_agent.run_live(br.wrapper, br.page, POLICY, vault, prompt,
                                        model=MODEL, max_steps=MAX_STEPS,
                                        budget=live_agent.Budget(BUDGET))
        finally:
            br.close()
    return {
        "answer": trace.get("final", ""),
        "steps": trace.get("steps", 0),
        "guard_killed_session": trace.get("killed", False),
        "incidents": [{"kind": i.kind, "detail": i.detail} for i in incidents.entries],
        "error": trace.get("error", ""),
    }
