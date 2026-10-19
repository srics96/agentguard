import pytest
from agentguard.policy import Policy, PolicyError

D = {
    "on_violation": "kill",
    "global": {"never_share": ["api_key"], "deny": ["delete"]},
    "categories": {"bank": {"domains": ["*.chase.com"], "deny": ["transfer"]}},
    "unknown_sites": {"deny": ["add_payee"]},
}


def test_category_matching():
    p = Policy.from_dict(D)
    assert p.category_of("https://secure.chase.com/x") == "bank"
    assert p.category_of("http://localhost:8000/") == "unknown"


def test_rules_only_add_restrictions():
    p = Policy.from_dict(D)
    bank = p.rules_for("https://secure.chase.com/x")
    assert "transfer" in bank.deny and "delete" in bank.deny  # global + category
    unk = p.rules_for("http://localhost/")
    assert "add_payee" in unk.deny and "delete" in unk.deny


def test_decide_action():
    p = Policy.from_dict(D)
    assert p.decide_action("https://secure.chase.com/x", "transfer") == "deny"
    assert p.decide_action("http://localhost/", "delete") == "deny"
    assert p.decide_action("http://localhost/", "interact") == "allow"


def test_unknown_action_type_rejected():
    with pytest.raises(PolicyError):
        Policy.from_dict({"global": {"deny": ["frobnicate"]}})
