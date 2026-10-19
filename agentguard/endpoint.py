"""A guarded browser endpoint: the pluggable "browser API".

GuardedEndpoint launches a real Chrome and attaches the CDP guard to it, then
exposes a normal CDP endpoint URL. Any agent — browser-use, an Operator-style
executor, a raw Playwright/Puppeteer client — connects to that URL exactly as
it would to an ordinary Chrome:

    ep = GuardedEndpoint(policy, vault); url = ep.start()
    # agent side, one line, no AgentGuard import:
    #   browser = playwright.chromium.connect_over_cdp(url)
    #   ... drive as usual; reads are redacted, leaks/denied requests blocked ...

The guard mediates at the protocol boundary, so the agent needs no integration
and cannot bypass it from its own code.

Guarantees and a known limitation:
  * EGRESS is enforced robustly for every connected agent — requests carrying a
    protected/tainted value or a denied action are blocked, so data cannot
    leave. This is the core guarantee and it holds across separate CDP
    connections.
  * RESPONSE REDACTION (blacking a secret out of what the agent sees) is applied
    per page once the guard has attached a Fetch session to it. When an external
    agent creates its own page and navigates it in the same instant, that page's
    *first* navigation can race the attach and not be redacted (egress is still
    blocked). Closing this race needs CDP Target auto-attach with
    waitForDebuggerOnStart, or a full CDP proxy — see the roadmap. The in-process
    paths (GuardedBrowser, CDPGuard.attach before navigation) have no such race.
"""
from __future__ import annotations

import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request

from playwright.sync_api import sync_playwright

from .cdp import CDPGuard
from .incidents import IncidentLog
from .policy import Policy


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _chrome_path() -> str:
    import glob
    hits = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))
    return hits[-1] if hits else (shutil.which("chromium") or shutil.which("google-chrome") or "")


class GuardedEndpoint:
    def __init__(self, policy: Policy, vault, incidents: IncidentLog | None = None,
                 headless: bool = True, chrome: str | None = None):
        self.policy = policy
        self.vault = vault
        self.incidents = incidents if incidents is not None else IncidentLog()
        self.headless = headless
        self.chrome = chrome or _chrome_path()
        self.port = None
        self._proc = None
        self._pw = None
        self._browser = None
        self.guard = None

    @property
    def cdp_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> str:
        """Launch guarded Chrome and return the CDP endpoint URL for agents."""
        self.port = _free_port()
        user_dir = tempfile.mkdtemp(prefix="agentguard-chrome-")
        args = [self.chrome, f"--remote-debugging-port={self.port}",
                f"--user-data-dir={user_dir}", "--no-first-run", "--no-default-browser-check",
                # container-friendly flags (root, no /dev/shm, no GPU)
                "--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
        if self.headless:
            args.append("--headless=new")
        self._proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._wait_ready()
        # Attach the guard over CDP; it watches existing and future pages.
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.connect_over_cdp(self.cdp_url)
        self.guard = CDPGuard(self.policy, self.vault, self.incidents)
        for ctx in self._browser.contexts:
            self.guard.attach_context(ctx)
        self._browser.on("context", lambda ctx: self.guard.attach_context(ctx))
        return self.cdp_url

    def _wait_ready(self, timeout=15):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                urllib.request.urlopen(f"{self.cdp_url}/json/version", timeout=1)
                return
            except Exception:
                time.sleep(0.2)
        raise RuntimeError("Chrome did not expose its CDP endpoint in time")

    def stop(self):
        for closer in (lambda: self._browser and self._browser.close(),
                       lambda: self._pw and self._pw.stop(),
                       lambda: self._proc and self._proc.terminate()):
            try:
                closer()
            except Exception:
                pass
