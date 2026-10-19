from agentguard.detect import (Vault, classify_element, classify_request,
                               find_sensitive, redact)


def kinds(hits):
    return sorted({h.kind for h in hits})


def test_api_key_and_ssh():
    txt = "OpenAI API Key: sk-proj-LeNAUZAwSKTX2cLHtrVsYcXP\nsshpass -p 'pw12345' ssh a@b -p 22"
    assert "api_key" in kinds(find_sensitive(txt))
    assert "ssh_credential" in kinds(find_sensitive(txt))


def test_labelled_card_fails_luhn_still_flagged():
    # The VPI-Bench note card number fails the Luhn checksum.
    assert "card_number" in kinds(find_sensitive("Card Number: 1581 2968 3058 2041"))


def test_luhn_valid_card_flagged_unlabelled():
    assert "card_number" in kinds(find_sensitive("pay 4242 4242 4242 4242 now"))


def test_random_long_number_not_a_card():
    assert "card_number" not in kinds(find_sensitive("order 1234567890123456 shipped"))


def test_vault_exact_match_any_spacing():
    v = Vault({"card": "1581 2968 3058 2041"})
    assert v.leaks_in("num=1581296830582041") == ["card"]
    assert v.leaks_in("num=1581-2968-3058-2041") == ["card"]


def test_vault_catches_base64_and_url_encoding():
    v = Vault({"key": "sk-proj-LeNAUZAwSKTX2cLHtrVsYcXP"})
    import base64, urllib.parse
    enc = base64.b64encode(b"sk-proj-LeNAUZAwSKTX2cLHtrVsYcXP").decode()
    assert v.leaks_in(f"payload={enc}") == ["key"]
    assert v.leaks_in("q=" + urllib.parse.quote("sk-proj-LeNAUZAwSKTX2cLHtrVsYcXP")) == ["key"]


def test_redact_blacks_out_secret():
    v = Vault({"ssh": "6gfL3J426c5K"})
    out, hits = redact("pw is 6gfL3J426c5K ok", {"api_key"}, v)
    assert "6gfL3J426c5K" not in out and hits


def test_classify_element_and_request():
    assert classify_element({"text": "Transfer money", "tag": "button"}) == "transfer"
    assert classify_element({"tag": "input", "type": "file"}) == "upload_file"
    assert classify_request("POST", "https://bank/transfer") == "transfer"
    assert classify_request("DELETE", "https://x/item/1") == "delete"
