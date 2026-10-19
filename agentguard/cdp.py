"""CDP-level interception: guard *any* browser agent, with no integration.

Instead of requiring the agent to call the GuardedBrowser action API, CDPGuard
attaches to the browser over the Chrome DevTools Protocol and mediates traffic
at the protocol boundary. Whatever library the agent uses (Playwright,
Puppeteer, Selenium, a raw CDP client), its network goes through here.

Two enforcement points are robust at the protocol layer and are the data-
protection core of the product:

  * READ  — response bodies are rewritten before they reach the renderer, so
    `never_see` data (and the user's exact secrets) are blacked out at the
    source. If the secret is not in the DOM, it is not in a screenshot either.
  * EGRESS— every request is inspected; one carrying a protected / never_share
    value, or performing a denied network action (transfer, delete, …), is
    failed before it leaves.

Action-intent policy (denying a *click* on "Transfer") stays in the action-API
guard (guard.py), because at the CDP layer a click is only a coordinate. The
two layers compose: CDPGuard for data in/out of any agent, GuardedBrowser when
the agent uses our API and we want per-action control too.
"""
from __future__ import annotations

import base64

from .detect import Vault, classify_request, find_sensitive, redact
from .incidents import Incident, IncidentLog
from .policy import Policy

_TEXTUAL = ("text/html", "application/json", "text/plain", "text/css",
            "application/javascript", "text/javascript", "application/xml", "text/xml")


class CDPGuard:
    def __init__(self, policy: Policy, vault: Vault, incidents: IncidentLog | None = None):
        self.policy = policy
        self.vault = vault
        self.incidents = incidents or IncidentLog()
        self._sessions = []

    def attach(self, page) -> None:
        """Attach to a page (and guard it). Call once per page; for a context,
        attach on every ``page`` event."""
        sess = page.context.new_cdp_session(page)
        sess.send("Fetch.enable", {"patterns": [{"requestStage": "Request"},
                                                 {"requestStage": "Response"}]})
        sess.on("Fetch.requestPaused", lambda e: self._on_paused(sess, e))
        self._sessions.append(sess)

    def attach_context(self, context) -> None:
        for pg in context.pages:
            self.attach(pg)
        context.on("page", self.attach)

    # ------------------------------------------------------------------ CDP

    def _on_paused(self, sess, e):
        rid = e["requestId"]
        is_response = "responseStatusCode" in e or "responseErrorReason" in e
        try:
            if is_response:
                self._handle_response(sess, e, rid)
            else:
                self._handle_request(sess, e, rid)
        except Exception:
            # Never wedge the page on an interception error; let it through.
            try:
                sess.send("Fetch.continueRequest" if not is_response
                          else "Fetch.continueResponse", {"requestId": rid})
            except Exception:
                pass

    def _handle_request(self, sess, e, rid):
        req = e["request"]
        url, method = req.get("url", ""), req.get("method", "GET")
        body = req.get("postData", "") or ""
        inc = self._inspect_egress(method, url, body)
        if inc:
            self.incidents.record(inc)
            sess.send("Fetch.failRequest", {"requestId": rid, "errorReason": "BlockedByClient"})
            return
        sess.send("Fetch.continueRequest", {"requestId": rid})

    def _handle_response(self, sess, e, rid):
        url = e["request"]["url"]
        headers = e.get("responseHeaders", []) or []
        ctype = ""
        for h in headers:
            if h.get("name", "").lower() == "content-type":
                ctype = h.get("value", "").lower()
        if not any(t in ctype for t in _TEXTUAL):
            sess.send("Fetch.continueResponse", {"requestId": rid})
            return
        got = sess.send("Fetch.getResponseBody", {"requestId": rid})
        raw = (base64.b64decode(got["body"]).decode("utf-8", "replace")
               if got.get("base64Encoded") else got.get("body", ""))
        kinds = {k for k in self.policy.rules_for(url).never_see if k != "protected"}
        cleaned, hits = redact(raw, kinds, self.vault)
        if hits:
            self.incidents.record(Incident(
                "read_redacted", f"redacted {sorted({h.kind for h in hits})} in response",
                url=url, data_kinds=sorted({h.kind for h in hits})))
        out_headers = [h for h in headers if h.get("name", "").lower() != "content-length"]
        sess.send("Fetch.fulfillRequest", {
            "requestId": rid, "responseCode": e.get("responseStatusCode", 200),
            "responseHeaders": out_headers,
            "body": base64.b64encode(cleaned.encode("utf-8")).decode()})

    # ------------------------------------------------------------- policy

    def _inspect_egress(self, method, url, body) -> Incident | None:
        rules = self.policy.rules_for(url)
        action = classify_request(method, url)
        if action and action in rules.deny:
            return Incident("leak_blocked", f"network {action}", url=url, action=action, killed=False)
        haystack = f"{url}\n{body}"
        leaked = self.vault.leaks_in(haystack)
        if leaked:
            return Incident("leak_blocked", f"protected value(s) {sorted(set(leaked))}",
                            url=url, data_kinds=["protected"], killed=False)
        share = {k for k in rules.never_share if k != "protected"}
        if share:
            hits = find_sensitive(body, share)
            if hits:
                return Incident("leak_blocked", f"never_share data {sorted({h.kind for h in hits})}",
                                url=url, data_kinds=sorted({h.kind for h in hits}), killed=False)
        return None
