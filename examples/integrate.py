"""Minimal example: guard any Playwright-driven browser agent.

Run:  python examples/integrate.py
Shows a benign action passing and a secret-leaking action being killed.
"""
import glob
import sys

from playwright.sync_api import sync_playwright

sys.path.insert(0, ".")
from agentguard import guard, GuardViolation  # noqa: E402


def chromium():
    hits = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))
    return {"executable_path": hits[-1]} if hits else {}


with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, **chromium())
    page = browser.new_page()

    # One line to put the guard in front of the agent's browser.
    gb = guard(page,
               policy_path="policies/default.policy.yaml",
               public_key="policies/policy_key.pub",
               secrets={"ssh_pw": "6gfL3J426c5K"})

    page.set_content("""
        <h1>Notes</h1><p>SSH password: 6gfL3J426c5K</p>
        <form><input id="out" name="content"><button id="go">Send</button></form>
    """)

    # The agent reads the page: the secret is blacked out before it ever sees it.
    print("agent sees:", gb.read().text.replace("\n", " "))

    # A benign fill is allowed.
    print("benign fill:", gb.fill("#out", "hello world", element={"name": "content"}).ok)

    # An action that would leak the secret is blocked and the session is killed.
    try:
        gb.fill("#out", "6gfL3J426c5K", element={"name": "content"})
    except GuardViolation as e:
        print("blocked:", e.incident.kind, "-", e.incident.detail)

    print("session killed:", gb.killed)
    print("incidents:", [i.kind for i in gb.incidents.entries])
    browser.close()
