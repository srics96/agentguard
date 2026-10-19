"""AgentGuard — a deterministic guard that sits in front of a browser agent.

Drop-in usage: give AgentGuard the Playwright page your agent would drive, a
signed policy, and the user's secret values. You get back a GuardedBrowser with
a small action API (navigate, read, click, fill, press, upload, screenshot).
Point your agent at that instead of the raw page, and every read is redacted,
every action is policy-checked, and every request is inspected — with no LLM in
the enforcement path.

    from agentguard import guard

    gb = guard(page,
               policy_path="policies/default.policy.yaml",
               public_key="policies/policy_key.pub",
               secrets={"api_key": "...", "ssh_pw": "..."})
    gb.navigate("https://example.com")
    text = gb.read().text          # secrets blacked out
    gb.fill("#msg", agent_value)   # blocked + session killed if it leaks a secret
"""
from __future__ import annotations

from .detect import Vault
from .guard import ActionResult, GuardedBrowser, GuardViolation, SessionKilled
from .incidents import Incident, IncidentLog
from .policy import Policy, PolicyError

__all__ = [
    "guard", "GuardedBrowser", "GuardViolation", "SessionKilled",
    "ActionResult", "Policy", "PolicyError", "Vault", "Incident", "IncidentLog",
]


def guard(page, policy_path, public_key=None, *, secrets=None,
          allow_unsigned: bool = False, incident_log_path=None) -> GuardedBrowser:
    """Wrap a Playwright ``page`` in the guard and return a GuardedBrowser.

    page               a Playwright Page the agent would otherwise drive.
    policy_path        path to the signed YAML policy.
    public_key         path to the Ed25519 public key; required unless
                       allow_unsigned is True (tests / local only).
    secrets            {name: value} of the user's real secrets to protect.
    incident_log_path  optional file to append incidents to (JSON lines).
    """
    policy = Policy.load(policy_path, public_key=public_key,
                         allow_unsigned=allow_unsigned)
    vault = Vault(dict(secrets or {}))
    log = IncidentLog(incident_log_path)
    return GuardedBrowser(page, policy, vault, log)
