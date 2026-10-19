# agentguard (early prototype)

Deterministic rule engine for guarding browser agents. Work in progress.

Included so far:
- `agentguard/detect.py`: regex/checksum detectors for sensitive data (API keys, SSH creds, cards, bank accounts, passports, balances), exact-match vault of the user's real values, redaction, and keyword classification of UI elements and requests into action types.
- `agentguard/policy.py`: layered standing rules (global -> category such as bank/airline/email), only ever adding restrictions; maps domains to categories.
- `agentguard/signing.py`: Ed25519 signing so a tampered policy file is refused at load.

Not yet built: the guarded browser that owns Chromium and enforces these rules, and the evaluation against VPI-Bench.

Known gap: the card detector only matches Luhn-valid numbers, so test numbers that fail Luhn are only caught via the vault.
