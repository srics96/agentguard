# Deploying the guarded agent to AWS Lightsail

This runs the **guarded browser-agent service** (`deploy/service.py`) — an LLM
browser agent that drives a headless Chromium **through AgentGuard**, exposed as
an HTTP API you talk to. A prompt-injected page cannot make it leak a protected
value or take a denied action.

## Pricing (be wary — this is the part that costs money)

Two separate costs:

1. **The Lightsail instance (fixed monthly).** The agent runs headless Chromium,
   which needs RAM. Recommended bundles:

   | Bundle | RAM | $/mo | Verdict |
   |---|---|---|---|
   | 512 MB | 0.5 GB | $3.50 | ❌ Chromium will OOM — don't |
   | **1 GB** | 1 GB | **$5** | ✅ minimum; fine for one task at a time (`--disable-dev-shm-usage` is set) |
   | 2 GB | 2 GB | $10 | ✅ safer headroom; use if you see OOM/crashes |

   Start on the **$5 / 1 GB** bundle. Lightsail often includes a **free first
   3 months** on the small bundles — check at create time. You can snapshot and
   resize up later without rebuilding.

2. **The model (usage-based, separate).** Each task calls OpenAI. With
   `gpt-4.1-mini` and the default 15-step cap, a task is roughly $0.01–0.05. The
   service caps spend **per task** via `AGENTGUARD_BUDGET_USD` (default $0.50) so
   a runaway task can't rack up cost. Set it low to be safe.

To avoid surprises: stop/delete the instance when you're done, and set a billing
alarm in the AWS console.

## Step 1 — create the instance

**Console:** Lightsail → Create instance → Linux/Unix → **OS Only → Ubuntu 22.04**
→ pick the **$5 (1 GB)** bundle → Create.

**Or CLI** (needs AWS CLI configured on your machine):

```bash
aws lightsail create-instances \
  --instance-names guarded-agent \
  --availability-zone us-east-1a \
  --blueprint-id ubuntu_22_04 \
  --bundle-id small_3_0            # small_3_0 = 1 GB / $5; medium_3_0 = 2 GB / $10
```

## Step 2 — open the port

Lightsail → your instance → **Networking** → add a firewall rule for **TCP 8080**
(restrict the source to your IP if you can — the service has no auth of its own;
see Security below).

## Step 3 — deploy

SSH into the instance (console "Connect using SSH", or your key), then:

```bash
export GH_PAT=ghp_your_token        # a token that can read the private repo
export OPENAI_API_KEY=sk-...        # the agent's model key
export AGENTGUARD_SECRETS='{"api":"sk-...","ssh_pw":"..."}'   # values to protect (optional)
curl -fsSL https://raw.githubusercontent.com/srics96/sricharans-personal-agent/main/deploy/bootstrap.sh | bash
```

`bootstrap.sh` installs Docker, clones the repo, builds the image, and runs the
service on port 8080 with your env (secrets are passed at runtime, never baked
into the image). First build takes a few minutes (it installs Chromium).

## How to talk to it

```bash
# health
curl http://<INSTANCE_IP>:8080/health

# run a task
curl -X POST http://<INSTANCE_IP>:8080/task \
  -H "Content-Type: application/json" \
  -d '{"goal": "Find the cheapest flight from SFO to NYC next Friday", "start_url": "https://www.google.com/travel/flights"}'
```

Response:

```json
{
  "answer": "…what the agent concluded…",
  "steps": 9,
  "guard_killed_session": false,
  "incidents": [{"kind": "read_redacted", "detail": "redacted ['api_key']"}],
  "error": ""
}
```

`incidents` is the audit trail — everything the guard redacted or blocked during
that task. If an injected page tried to exfiltrate a protected value, you'll see
a `leak_blocked` incident and the value will not have left.

## Security notes (important)

- **The service has no built-in auth.** Do not expose port 8080 to the whole
  internet. Restrict the Lightsail firewall rule to your IP, or put it behind a
  reverse proxy (Caddy/nginx) with a token or basic auth.
- **Real sites need real policies.** The shipped policy is tuned for the demo /
  benchmark. Before pointing the agent at your real bank/email, write a policy
  for those domains (what it may read, deny all writes, nothing leaves) and
  re-sign it. See the main README.
- Keep `policy_key.pem` off the instance and the repo; only the signed policy and
  the public key are needed to run.
