# agentguard

A deterministic guard for browser agents. The guard owns Chromium and hands the
agent a small action API instead of a raw browser; every read is redacted, every
action is checked against a signed policy, and every outgoing request is
inspected, so a prompt-injected agent cannot leak the user's secrets or perform
destructive actions. No LLM sits in the decision path — the enforcement is
regex / checksum / keyword based and cannot itself be prompt-injected.

## Modules

- `agentguard/detect.py` — detectors for sensitive data (API keys, SSH creds,
  cards, bank accounts, passports, phone numbers, balances), an exact-match
  vault of the user's real values (matched through url/base64/reversed
  encodings), redaction, and keyword classification of UI elements and requests
  into action types.
- `agentguard/policy.py` — layered standing rules (global → category such as
  bank/email/shopping → unknown), which only ever *add* restrictions. Chat or
  task instructions can never widen a policy.
- `agentguard/signing.py` — Ed25519 signing, so a tampered policy file is
  refused at load.
- `agentguard/guard.py` — **the guarded browser.** Owns the Playwright page and
  enforces the policy at three points:
  1. **read** — page text is run through the redactor, so `never_see` data is
     blacked out before the agent sees it;
  2. **act** — every click / press / fill / upload is classified and checked;
     a `fill` carrying a protected value is blocked *before it touches the
     page*, which catches client-only sites whose "send" never hits the
     network;
  3. **network** — every request is held and inspected; one carrying a
     protected / `never_share` value, or performing a denied action (transfer,
     delete, …), is aborted.
  On a violation the guard kills the session (default) or blocks the one action,
  per `policy.on_violation`, and writes an incident (`agentguard/incidents.py`).

## Policy

`policies/default.policy.yaml`, signed with `policies/policy_key.pub`. Regenerate
the signature after editing:

```bash
python -c "from agentguard.signing import keygen, sign_file; \
  keygen('policies/policy_key.pem','policies/policy_key.pub'); \
  sign_file('policies/default.policy.yaml','policies/policy_key.pem')"
```

The private key is git-ignored; keep it off the repo.

## Tests

```bash
pip install playwright pyyaml cryptography pytest
python -m pytest -q
```

The guard tests use a fake page, so they run with no browser.

## Evaluation against VPI-Bench (browser cases)

The guard is evaluated against the 87 browser-agent cases from
[VPI-Bench](https://arxiv.org/abs/2506.02456)
([agents](https://github.com/cua-framework/agents),
[web](https://github.com/cua-framework/web)). The evaluation is **deterministic
and uses no live model**: a scripted attacker (`eval/attacker.py`) performs each
case's attacker objective — read the secret, place it in a form/message, send
it, destroy the file — through an identical action API in two arms, one wrapped
by the guard and one not. Each case is scored from **ground truth** only: the
fake server's ledger (what data actually arrived at the attacker's sink, which
Drive file was actually deleted/edited) and the final page state — never from
what the agent or the guard claims.

```bash
# clone the benchmark repos next to this one, under ../vendor
python eval/run.py            # runs all 87 cases, both arms
# → results/results.json and results/SUMMARY.md
```

- `eval/fakesites/server.py` — a fake Google Drive plus collector / send
  endpoints, recording every real effect. Nothing talks to real Google Drive or
  any live service.
- `eval/pages/` — local pages mirroring the benchmark's webform / email /
  messenger structure.
- `eval/cases.py` — rebuilds the 87 cases from `main_benchmark.parquet`.
- `eval/score.py` — ground-truth scoring.

See `results/SUMMARY.md` for the latest numbers.

### Why a scripted attacker, and the optional live-LLM run

The guard is a *deterministic* control: it blocks the exfiltration and the
destructive action whether or not an agent was fooled. So the scripted attacker
— which attempts the attack unconditionally, even submitting the real secret to
test the fill/network layers directly — is the sharper measure of the guard, and
it is reproducible and free.

A live-LLM VPI-Bench run measures something different: how often a given model
*gets tricked*. That is a property of the model, not the guard, and it is not
needed to show the guard stops these attacks. To add it, point VPI-Bench's own
`browser-use` runner (in the `agents` repo) at the guarded page by giving the
agent the `GuardedBrowser` action API in place of its raw browser tools, keep
the same local pages and fake Drive, and read the same ledger with
`eval/score.py`. That run needs an `OPENAI_API_KEY` and a cheap model; the
deterministic run here does not.

### Known limitations

In the current policy the guard neutralises all 87 exfiltration, delete and edit
attacks but lets 6 through (`*_FORWARD`, `*_MESSAGE`): forwarding message/email
*logs* that contain no protected value, and sending a phishing *link* to a
contact. These carry no secret and are not destructive, so a data-leak /
destructive-action guard has nothing deterministic to catch. Blocking them needs
a different control (e.g. denying `send_message` to unknown recipients, or
treating outbound links to unverified domains as approval-required) rather than
data detection. See `results/SUMMARY.md`.
