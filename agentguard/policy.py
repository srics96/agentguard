"""Standing rules: loaded once, signed by the user, never editable by the agent.

A policy is layered:  global  ->  category (bank, airline, email, ...)
Chat / task instructions can never widen it; only a re-signed policy can.
"""
from __future__ import annotations

import fnmatch
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ACTION_TYPES = {
    "transfer", "add_payee", "account_change", "purchase", "delete", "send_message",
    "edit_file", "upload_file", "submit_form", "interact", "navigate", "run_script",
}
DATA_KINDS = {"api_key", "ssh_credential", "password", "card_number", "bank_account",
              "phone", "passport", "balance", "protected"}


class PolicyError(Exception):
    pass


@dataclass
class Rules:
    deny: set[str] = field(default_factory=set)
    approve: set[str] = field(default_factory=set)
    never_see: set[str] = field(default_factory=set)
    never_share: set[str] = field(default_factory=set)
    deny_pages: list[str] = field(default_factory=list)
    # provenance / taint: treat data read here as private, and the only sinks
    # that private/tainted data may be sent to.
    taint_reads: bool = False
    allow_sinks: list[str] = field(default_factory=list)
    # outbound-link control: hold messages carrying links to domains not listed.
    deny_outbound_links: bool = False
    allow_link_domains: list[str] = field(default_factory=list)

    def merged(self, other: "Rules") -> "Rules":
        # Merging only ever *adds* restrictions.
        return Rules(self.deny | other.deny, self.approve | other.approve,
                     self.never_see | other.never_see, self.never_share | other.never_share,
                     self.deny_pages + other.deny_pages,
                     self.taint_reads or other.taint_reads,
                     self.allow_sinks + other.allow_sinks,
                     self.deny_outbound_links or other.deny_outbound_links,
                     self.allow_link_domains + other.allow_link_domains)


def _rules(d: dict | None, where: str) -> Rules:
    d = d or {}
    r = Rules(set(d.get("deny", [])), set(d.get("approve", [])), set(d.get("never_see", [])),
              set(d.get("never_share", [])), list(d.get("deny_pages", [])),
              bool(d.get("taint_reads", False)), list(d.get("allow_sinks", [])),
              bool(d.get("deny_outbound_links", False)), list(d.get("allow_link_domains", [])))
    bad = (r.deny | r.approve) - ACTION_TYPES
    if bad:
        raise PolicyError(f"{where}: unknown action types {sorted(bad)}")
    bad = (r.never_see | r.never_share) - DATA_KINDS
    if bad:
        raise PolicyError(f"{where}: unknown data kinds {sorted(bad)}")
    return r


@dataclass
class Policy:
    global_rules: Rules
    categories: dict[str, tuple[list[str], Rules]]
    unknown: Rules
    on_violation: str = "kill"           # kill | block
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "Policy":
        cats = {}
        for name, c in (d.get("categories") or {}).items():
            cats[name] = (list(c.get("domains", [])), _rules(c, f"categories.{name}"))
        on_v = d.get("on_violation", "kill")
        if on_v not in ("kill", "block"):
            raise PolicyError("on_violation must be kill or block")
        return cls(_rules(d.get("global"), "global"), cats, _rules(d.get("unknown_sites"), "unknown_sites"), on_v, d)

    @classmethod
    def load(cls, path: str | Path, public_key: str | Path | None = None, allow_unsigned: bool = False) -> "Policy":
        from .signing import verify_file
        path = Path(path)
        data = path.read_bytes()
        if public_key:
            verify_file(path, public_key)
        elif not allow_unsigned:
            raise PolicyError("refusing to load an unsigned policy (pass a public key or allow_unsigned=True)")
        return cls.from_dict(yaml.safe_load(data))

    def category_of(self, url: str) -> str:
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        for name, (domains, _) in self.categories.items():
            if any(fnmatch.fnmatch(host, pat) for pat in domains):
                return name
        return "unknown"

    def rules_for(self, url: str) -> Rules:
        cat = self.category_of(url)
        base = self.global_rules
        if cat == "unknown":
            return base.merged(self.unknown)
        return base.merged(self.categories[cat][1])

    def decide_action(self, url: str, action: str) -> str:
        """allow | approve | deny"""
        r = self.rules_for(url)
        if action in r.deny:
            return "deny"
        if action in r.approve:
            return "approve"
        return "allow"

    def page_denied(self, url: str) -> str | None:
        r = self.rules_for(url)
        u = url.lower()
        for pat in r.deny_pages:
            if fnmatch.fnmatch(u, pat.lower()):
                return pat
        return None
