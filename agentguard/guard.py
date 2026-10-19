"""The guarded browser.

The guard launches and owns Chromium through Playwright. The agent never gets
a CDP connection; it only gets the small, synchronous action API on
``GuardedBrowser`` (navigate, read, click, fill, press, upload, screenshot).

Three enforcement points, all deterministic (no LLM in the decision path):

  1. READ  - every bit of text handed back to the agent is run through the
     redactor, so ``never_see`` data is blacked out before the agent sees it.
  2. ACT   - every click / press / fill / upload is classified and checked
     against the policy for the current page before it touches the page.
  3. NET   - every outgoing request is held and inspected; a request carrying a
     protected / never_share value, or performing a denied action (transfer,
     delete, ...), is aborted.

On a violation the guard either kills the session (default) or blocks the one
action, according to ``policy.on_violation``. Either way it writes an incident.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass

from .detect import (TaintTracker, Vault, classify_element, classify_request,
                     find_sensitive, link_host, links_in, redact)
from .incidents import Incident, IncidentLog
from .policy import Policy


class GuardViolation(Exception):
    """Raised (when on_violation == 'kill') to tear the session down."""

    def __init__(self, incident: Incident):
        super().__init__(f"{incident.kind}: {incident.detail}")
        self.incident = incident


class SessionKilled(Exception):
    """Any action attempted after the guard has killed the session."""


@dataclass
class ActionResult:
    ok: bool
    detail: str = ""
    text: str = ""


class GuardedBrowser:
    """Owns the page and mediates every interaction with it.

    ``page`` is any object offering the handful of Playwright methods used
    below (goto, inner_text, click, fill, press, set_input_files, screenshot,
    url, route/unroute). The real Chromium page is supplied by ``launch`` in
    runner code; tests pass a fake page, so the enforcement logic can be
    exercised with no browser.
    """

    def __init__(self, page, policy: Policy, vault: Vault,
                 incidents: IncidentLog | None = None):
        self.page = page
        self.policy = policy
        self.vault = vault
        self.taint = TaintTracker()
        self.incidents = incidents if incidents is not None else IncidentLog()
        self.killed = False
        self._install_network_guard()

    # -------------------------------------------------- network enforcement

    def _install_network_guard(self):
        route = getattr(self.page, "route", None)
        if route is None:
            return

        def handler(route_obj, request):
            try:
                verdict = self._inspect_request(request.method, request.url,
                                                _request_body(request))
            except Exception:
                # A bug in inspection must not brick the page; let it through.
                route_obj.continue_()
                return
            if verdict is None:
                route_obj.continue_()
            else:
                route_obj.abort()
                self._violation(verdict)

        route("**/*", handler)

    def _inspect_request(self, method: str, url: str, body: str) -> Incident | None:
        """Return an Incident if the request must be blocked, else None."""
        rules = self.policy.rules_for(url)

        # 1. denied action performed over the network (transfer, delete, ...)
        action = classify_request(method, url)
        if action and action in rules.deny:
            return Incident("leak_blocked", f"network {action} to {_host(url)}",
                            url=url, action=action)

        # 2. protected / never_share values leaving in the payload
        haystack = f"{url}\n{body}"
        leaked = self.vault.leaks_in(haystack)
        if leaked:
            return Incident("leak_blocked",
                            f"protected value(s) {sorted(set(leaked))} to {_host(url)}",
                            url=url, data_kinds=["protected"])

        share_kinds = rules.never_share & {"api_key", "ssh_credential", "password",
                                           "card_number", "bank_account", "passport",
                                           "phone"}
        if share_kinds:
            hits = find_sensitive(body, share_kinds)
            if hits:
                kinds = sorted({h.kind for h in hits})
                return Incident("leak_blocked",
                                f"never_share data {kinds} to {_host(url)}",
                                url=url, data_kinds=kinds)
        # Taint is checked against url+body (a secret can hide in either); the
        # outbound-link rule is checked against the body only, never the URL
        # being fetched - navigating to a page is not "sending a link".
        return self._taint_link_incident(f"{url}\n{body}", body, _host(url), rules, url, "")

    def _taint_link_incident(self, taint_text: str, link_text: str, dest_host: str,
                             rules, url: str, action: str) -> Incident | None:
        """Shared egress check: tainted (private-origin) data leaving to a sink
        that is not allow-listed, or an outbound link to an unlisted domain."""
        tainted = self.taint.leaks_in(taint_text)
        if tainted and not _host_allowed(dest_host, rules.allow_sinks):
            return Incident("leak_blocked",
                            f"private data {sorted(set(tainted))[:3]} to {dest_host or 'sink'}",
                            url=url, action=action, data_kinds=["tainted"])
        if rules.deny_outbound_links:
            bad = [h for h in (link_host(u) for u in links_in(link_text))
                   if h and not _host_allowed(h, rules.allow_link_domains)]
            if bad:
                return Incident("leak_blocked", f"outbound link to {sorted(set(bad))[:3]}",
                                url=url, action=action or "send_message", data_kinds=["link"])
        return None

    # ---------------------------------------------------------- agent API

    def _check_alive(self):
        if self.killed:
            raise SessionKilled("session was killed by the guard")

    def navigate(self, url: str) -> ActionResult:
        self._check_alive()
        denied = self.policy.page_denied(url)
        if denied:
            self._violation(Incident("page_denied", f"navigation to {url} (matched {denied})",
                                      url=url, action="navigate"))
            return ActionResult(False, "navigation denied")
        self.page.goto(url)
        return ActionResult(True, url)

    def read(self, selector: str | None = None) -> ActionResult:
        """Return page text with never_see data for this page redacted."""
        self._check_alive()
        raw = self.page.inner_text(selector) if selector else self.page.inner_text("body")
        rules = self.policy.rules_for(self._url())
        if rules.taint_reads:
            # Everything read from a private page becomes protected from here on,
            # even values we never registered up front.
            self.taint.observe(raw)
        kinds = _see_kinds(rules.never_see)
        cleaned, hits = redact(raw, kinds, self.vault)
        if hits:
            self.incidents.record(Incident(
                "read_redacted", f"redacted {sorted({h.kind for h in hits})}",
                url=self._url(), data_kinds=sorted({h.kind for h in hits})))
        return ActionResult(True, text=cleaned)

    def click(self, selector: str, element: dict | None = None) -> ActionResult:
        self._check_alive()
        action = classify_element(element) if element else "interact"
        if not self._allow_action(action):
            return ActionResult(False, f"action '{action}' denied")
        self.page.click(selector)
        return ActionResult(True, action)

    def fill(self, selector: str, value: str, element: dict | None = None) -> ActionResult:
        """Fill a field. A fill that would place a protected / never_share value
        into a form on this page is itself a leak and is blocked here, before
        any network request - this is what catches the client-only fake sites
        whose 'send' never touches the network."""
        self._check_alive()
        action = classify_element(element) if element else "submit_form"
        rules = self.policy.rules_for(self._url())
        leaked = self.vault.leaks_in(value)
        if leaked:
            self._violation(Incident("leak_blocked",
                                     f"fill with protected value(s) {sorted(set(leaked))}",
                                     url=self._url(), action=action,
                                     data_kinds=["protected"]))
            return ActionResult(False, "fill carries protected data")
        share_kinds = _see_kinds(rules.never_share)
        if share_kinds:
            hits = find_sensitive(value, share_kinds)
            if hits:
                kinds = sorted({h.kind for h in hits})
                self._violation(Incident("leak_blocked",
                                         f"fill with never_share data {kinds}",
                                         url=self._url(), action=action, data_kinds=kinds))
                return ActionResult(False, "fill carries never_share data")
        inc = self._taint_link_incident(value, value, _host(self._url()), rules, self._url(), action)
        if inc:
            self._violation(inc)
            return ActionResult(False, inc.detail)
        self.page.fill(selector, value)
        return ActionResult(True, action)

    def press(self, selector: str, key: str, element: dict | None = None) -> ActionResult:
        self._check_alive()
        # Enter on a form control is a submit; classify the element for intent.
        action = classify_element(element) if element else "interact"
        if key == "Enter" and action == "interact":
            action = "submit_form"
        if not self._allow_action(action):
            return ActionResult(False, f"action '{action}' denied")
        self.page.press(selector, key)
        return ActionResult(True, action)

    def upload(self, selector: str, path: str) -> ActionResult:
        self._check_alive()
        if not self._allow_action("upload_file"):
            return ActionResult(False, "upload denied")
        self.page.set_input_files(selector, path)
        return ActionResult(True, "upload_file")

    def screenshot(self, path: str | None = None) -> ActionResult:
        self._check_alive()
        data = self.page.screenshot(path=path) if path else self.page.screenshot()
        return ActionResult(True, "screenshot", text=str(path or len(data or b"")))

    # ---------------------------------------------------------- internals

    def _allow_action(self, action: str) -> bool:
        decision = self.policy.decide_action(self._url(), action)
        if decision == "deny":
            self._violation(Incident("action_denied", f"action '{action}' denied by policy",
                                      url=self._url(), action=action))
            return False
        # 'approve' with no human present is treated as deny in autonomous runs.
        if decision == "approve":
            self._violation(Incident("action_denied",
                                     f"action '{action}' needs approval; none available",
                                     url=self._url(), action=action))
            return False
        return True

    def _violation(self, inc: Incident):
        if self.policy.on_violation == "kill":
            inc.killed = True
            self.incidents.record(inc)
            self._kill()
            raise GuardViolation(inc)
        self.incidents.record(inc)

    def _kill(self):
        self.killed = True
        for m in ("close",):
            fn = getattr(self.page, m, None)
            if callable(fn):
                try:
                    fn()
                except Exception:
                    pass

    def _url(self) -> str:
        u = getattr(self.page, "url", "")
        return u() if callable(u) else (u or "")


def _see_kinds(names: set[str]) -> set[str]:
    """Concrete data kinds for the detectors; 'protected' is handled by the
    vault, not by find_sensitive, so it is dropped here."""
    return {k for k in names if k != "protected"}


def _host(url: str) -> str:
    return (urllib.parse.urlsplit(url).hostname or url).lower()


def _host_allowed(host: str, patterns: list[str]) -> bool:
    import fnmatch
    host = (host or "").lower()
    return any(fnmatch.fnmatch(host, p.lower()) for p in patterns)


def _request_body(request) -> str:
    for attr in ("post_data", "postData"):
        v = getattr(request, attr, None)
        if callable(v):
            try:
                return v() or ""
            except Exception:
                return ""
        if isinstance(v, str):
            return v
    return ""
