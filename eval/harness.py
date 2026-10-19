"""Launch a real Chromium page, wrapped either by the guard or by nothing.

Both wrappers expose the same action API, so the scripted attacker
(attacker.py) is byte-for-byte identical in the guarded and unguarded arms.
The only difference between the two runs is whether the guard is in the path.
"""
from __future__ import annotations

import glob
import os
from dataclasses import dataclass

from playwright.sync_api import sync_playwright

from agentguard.detect import Vault
from agentguard.guard import ActionResult, GuardedBrowser
from agentguard.incidents import IncidentLog
from agentguard.policy import Policy


def chromium_path() -> str:
    env = os.environ.get("AGENTGUARD_CHROME")
    if env:
        return env
    hits = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))
    if hits:
        return hits[-1]
    return ""  # fall back to Playwright's own resolution


class RawBrowser:
    """Unguarded arm: the same API, but every action goes straight to the page
    with no redaction and no checks."""

    def __init__(self, page):
        self.page = page
        self.killed = False
        self.incidents = IncidentLog()

    def navigate(self, url):
        self.page.goto(url); return ActionResult(True, url)

    def read(self, selector=None):
        return ActionResult(True, text=self.page.inner_text(selector or "body"))

    def fill(self, selector, value, element=None):
        self.page.fill(selector, value); return ActionResult(True)

    def click(self, selector, element=None):
        self.page.click(selector); return ActionResult(True)

    def press(self, selector, key, element=None):
        self.page.press(selector, key); return ActionResult(True)

    def upload(self, selector, path, element=None):
        self.page.set_input_files(selector, path); return ActionResult(True)

    def screenshot(self, path=None):
        self.page.screenshot(path=path) if path else self.page.screenshot()
        return ActionResult(True)


@dataclass
class Browser:
    wrapper: object
    page: object
    context: object
    browser: object
    pw: object

    def close(self):
        for obj in (self.context, self.browser, self.pw):
            try:
                getattr(obj, "close", getattr(obj, "stop", lambda: None))()
            except Exception:
                pass


def launch(guarded: bool, policy: Policy, vault: Vault,
           incidents: IncidentLog | None = None) -> Browser:
    pw = sync_playwright().start()
    exe = chromium_path()
    kw = {"headless": True}
    if exe:
        kw["executable_path"] = exe
    browser = pw.chromium.launch(**kw)
    context = browser.new_context()
    page = context.new_page()
    wrapper = (GuardedBrowser(page, policy, vault, incidents) if guarded
               else RawBrowser(page))
    return Browser(wrapper, page, context, browser, pw)
