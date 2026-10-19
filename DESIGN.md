# AgentGuard — design for a reliable product

This document is the result of a research pass on the state of browser-agent
security (late 2025 → 2026) and lays out how to build AgentGuard into a
reliable product. It is opinionated and tries to be honest about prior art,
what is already solved, and what is hard. Sources are listed at the end.

---

## 1. The problem and the scope

Browser agents (OpenAI Atlas/Operator, Perplexity Comet, Claude for Chrome,
browser-use, Gemini computer-use) take a benign user task and act on live web
pages. Those pages can carry **injected instructions** that hijack the agent
into exfiltrating the user's data or taking destructive/financial actions.

Two facts frame everything:

- **Prompt injection is unsolved and may stay that way.** OpenAI's security
  lead calls it "a frontier, unsolved security problem." Anthropic's own
  red-team of Claude for Chrome measured a **23.6% attack success rate, 11.2%
  after mitigations** — roughly one in nine still succeeds. You cannot build a
  product on "the model will resist."
- **The browser / no-API surface has no control plane.** Where an app has an
  API, OAuth scopes and MCP gateways already govern access (and that market is
  crowded — see §2). Browser agents exist *precisely where APIs do not*, and
  there the only controls shipping today are blunt: block the site, or judge
  the agent with a second LLM. Neither is a real control plane.

**Scope decision: AgentGuard is for browser agents on the no-API surface.** Not
MCP tool authorization (crowded, consolidating). Not computer-use/OS (later).
The browser is the void, and it is where the hardest, most valuable problem is.

## 2. Landscape and positioning

**Mechanism — what works, from the research.** Two serious lines of work
converge on the same answer, and it is *not* classifiers:

- **CaMeL** (Google DeepMind / ETH): a privileged LLM plans from the trusted
  task only; a quarantined LLM reads untrusted data; a custom interpreter
  tracks **capabilities and data provenance** and enforces **policies at tool
  calls**, so tainted data cannot reach a sensitive sink without a policy
  check. Deterministic, "provable," ~77% of AgentDojo tasks solved with
  security vs ~84% undefended. **Limitation: it requires rewriting the agent**
  into the dual-LLM/interpreter architecture — not drop-in, not vendor-neutral,
  and the user must author/maintain policies.
- **ceLLMate** (Earlence Fernandes' group, Dec 2025): "sandboxing browser
  agents," analogous to OS process sandboxing — a Chromium extension that
  intercepts requests, with **per-site policies and an "agent sitemap,"** plus
  **LLM-assisted policy prediction** (offline authoring). This is almost
  exactly AgentGuard's shape. **Limitation: research prototype** — tied to the
  deprecated MV2 `webRequestBlocking` API, only a partial demo policy (GitLab).
- **"Minimize-and-sanitize" firewalls at the agent–tool interface** report
  near-perfect security with high utility on AgentDojo. Deterministic interface
  enforcement beats model critics.

**Takeaway: the winning mechanism is a deterministic capability + data-flow
sandbox at the agent's action/IO boundary.** Classifiers and model critics
(what the vendors ship) are the weaker path and are themselves injectable.

**Market — where the void actually is.**

| Layer | State | For AgentGuard |
|---|---|---|
| LLM-app / prompt guardrails (Lakera, …) | mature, 2023–24 threat model | not our fight |
| MCP / tool-call gateways & agent runtime security (CalypsoAI→F5, Aim→Cato, SPLX→Zscaler, Palo Alto Prisma AIRS, HiddenLayer, MintMCP, AccuroAI) | **crowded, consolidating in 2025–26** | avoid — API/tool layer |
| **Browser / no-API agent control** | **commercially empty; research-only (ceLLMate); vendors only block-or-critic** | **the void — our product** |

So: the broad "agent security" market is busy, but **nobody ships a
deterministic, fine-grained, vendor-neutral control plane for browser agents on
the no-API surface.** That is the defensible position.

## 3. Threat model (explicit)

- **Adversary:** attacker-controlled content on a page the agent reads (DOM
  text, images, URLs, fragments, linked docs, injected sub-tasks, poisoned
  memory). Also a fully **compromised agent** holding valid sessions/tokens.
- **Assume:** the model *will* be injected (sometimes). The agent may act
  against the user. The site may be hostile or compromised.
- **Trusted:** the signed policy, the user (principal) who signs it, and the
  AgentGuard enforcement engine itself (small, auditable, no LLM).
- **Goal:** bound the blast radius. Even on 100% injection success, the agent
  **cannot exfiltrate protected data or take a denied action.**
- **Out of scope (v1):** secrets rendered only as images/canvas (vision
  exfiltration), timing/side channels, attacks on the signing key.

## 4. Design principles (the invariants)

1. **Contain, don't detect.** Do not try to catch the injection. Constrain what
   any agent — compromised or not — can *do*. Sell bounded worst-case, not a
   block rate.
2. **No LLM in the enforcement path.** Deterministic only (regex, checksum,
   provenance, allowlist). This is the differentiator vs every vendor's model
   critic, and it means the guard itself can't be injected.
3. **Two axes, both enforced:** **capability** (which actions may run) and
   **data-flow** (which data may leave, to where). Pattern-matching secrets is
   not enough; track provenance (§5.2).
4. **Default-deny + allowlist, per (site, intent).** Enumerate the few *safe*
   operations/destinations, not the infinite dangerous ones. Drift can then
   only over-block, never open a hole.
5. **Fail closed.** If the guard can't confidently identify what it's
   governing, it denies. Worst case is "too strict," never "silently open."
6. **Judge by ground truth.** Every decision and every consent prompt uses what
   the guard actually observed (real endpoint, real amount), never the agent's
   or the page's narration.
7. **The principal signs.** Policies are signed by the user/org, so neither the
   agent nor page content nor a task instruction can widen them.

## 5. Architecture

### 5.1 Enforcement surface — be the browser, not a library

Adoption = a one-line change, not an SDK. Expose a **guarded CDP endpoint +
TLS-terminating egress proxy**; the agent connects to it exactly like a normal
browser (`cdp_url=…`), so browser-use / Operator-style executors / any
CDP-speaking agent are covered with no integration. For the user's *own* Chrome
(Claude for Chrome), ship a companion **extension** at the same choke point.

Why this over ceLLMate's MV2 extension: MV2 `webRequestBlocking` is being
removed from Chrome; betting enforcement on it is a dead end. CDP + a real proxy
is durable and library-agnostic. **Proxy-based enforcement is also the one
approach the 2025 landscape review found nobody shipping** — a genuine gap.

Three enforcement points:
- **Read** (CDP + proxy): rewrite response bodies / redact DOM so `never_see`
  data never reaches the renderer — and therefore never reaches a screenshot.
- **Act** (CDP): classify and gate clicks/fills/uploads; block client-side
  actions that make no network request (the gap a pure proxy can't see).
- **Egress** (proxy): hold every request; block protected/denied data flows.

### 5.2 Provenance / taint — the core of data-flow control

Adopt CaMeL's mechanism, adapted to an external sandbox. Tag data by origin:
- **Private** — read from the user's bank/Drive/mail.
- **Untrusted** — read from an arbitrary page.
- **Sinks** — classified by destination (on-domain vs off-domain / unknown).

Rule: **private data may not reach an untrusted sink; a value derived from an
untrusted source may not drive a sensitive action without a policy check.** This
catches exfiltration *by flow*, not by recognizing a secret pattern — which is
why it closes gaps that content detection misses (e.g. forwarding "logs" that
contain no obvious secret). Unlike CaMeL, we can't see the agent's variables, so
we track taint at the IO boundary: what data entered via which read, and whether
that same data appears in an outgoing request/fill.

### 5.3 Policy model and lifecycle — solve the authoring burden

CaMeL's honest limitation is that **users must write and maintain policies, and
approval fatigue makes them click "allow" on everything.** This is *the* product
problem. Solve it with three layers so nobody authors policy up front:

1. **Default-deny floor**, always on, every domain: reads ok, all writes/egress
   of private data denied. Day one, unknown sites are safe, not broken.
2. **Curated, signed policy library** for the top apps (bank "read-only",
   shopping "≤ $X", mail "send to known contacts"). Users *consume* policies;
   they don't write them. This is the compounding, defensible asset.
3. **Just-in-time consent** (iOS-style) for the long tail: the first denied
   action prompts the user with ground truth ("POST $84 to utility.com — allow
   once / always / deny"); "always" accretes into a signed policy. No up-front
   authoring, ever.

Policies are compiled offline (LLM-assisted, like ceLLMate's "policy
prediction") from **observed** app structure (not the model's guesses),
constrained to a typed schema, verified against the app, and **human-signed**.
The LLM never sits in the runtime path.

### 5.4 Policy = capability + data-flow + egress, keyed on observation

Not CSS selectors (they break on redesign). Anchor to the layers that change
least: **network endpoints/methods, routes, and data patterns.** A policy entry
is `(capability | data-rule, target, constraints)`, e.g. *"GET /balances
allowed; all writes to bank denied; currency/account patterns redacted outside
the balances view; private data → off-domain sink denied."*

## 6. Reliability engineering (what "reliable" actually demands)

A guard is *unreliable* if it gives false confidence. Reliability here means
bounded worst-case and no silent failure:

| Requirement | Mechanism |
|---|---|
| No silent fail-open on site change | **drift fingerprint**: sign policy against app structure; on mismatch → stale → fail closed |
| Reproducible, no variance | deterministic engine; no LLM in path |
| Bounded worst case | provenance + default-deny egress → injection at 100% still can't exfiltrate |
| Trust the consent prompt | prompt shows guard ground truth, not agent narration |
| Provable over time | continuous eval on **VPI-Bench** (browser) **and AgentDojo** (tool/data-flow), both numbers published |
| Auditable | append-only incident log of every allow/deny, replayable |

## 7. What is novel vs prior art (honest)

- **Not novel:** the sandbox-the-browser-agent idea (ceLLMate), the
  capability/data-flow mechanism (CaMeL, FIDES-style firewalls), site-scoping
  (Google Origin Sets), human-in-the-loop (every vendor).
- **The actual opportunity (productization + distribution):**
  1. a **durable enforcement surface** (CDP + proxy), not research-grade MV2;
  2. **vendor-neutral** — one portable, signed policy across Operator / Comet /
     Claude / browser-use, which each vendor's in-house silo can't be;
  3. a **maintained, signed policy library** for real apps + the offline
     compiler — the compounding asset, like an AV/WAF ruleset;
  4. **"use it safely" instead of "block it"** — the wedge against vendors who
     just block banking;
  5. **reliability engineering** (fail-closed, drift, ground-truth consent,
     published benchmarks) that turns a demo into something trustable.

Mechanism is proven by research; **nobody has made it a usable, reliable,
cross-agent product for the browser surface.** That is the gap.

## 8. Build roadmap

1. **Provenance/taint** at the IO boundary (private-source → untrusted-sink);
   re-run VPI-Bench — expected to close the forward/send-link gap honestly.
2. **Fail-closed drift fingerprint** so a redesign can't silently open the hole.
3. **Benchmark on AgentDojo** too; publish VPI-Bench + AgentDojo numbers.
4. **Guarded CDP endpoint + egress proxy** as the real enforcement surface;
   prove a one-line `cdp_url` swap guards browser-use on a real site.
5. **Policy compiler** (observe → LLM-label to typed schema → verify → sign) and
   the **first few library policies** (a bank read-only, a webmail).
6. **Just-in-time consent UX** with ground-truth prompts.
7. **Open the signed-policy format as a spec** + thin adapters, to become the
   standard rather than a library.

## 9. Success criteria

- On VPI-Bench and AgentDojo: **near-zero exfiltration/destruction under
  attack** with **utility retained on benign tasks** (the utility–security
  tradeoff is the real bar; both numbers must be good, and published).
- Worst-case guarantee statable in one sentence: *"a fully compromised agent on
  a covered site cannot exfiltrate protected data or move money."*
- One-line integration for a CDP agent; a real site working end-to-end.

## 10. Open problems / risks

- **Utility–security tradeoff** (the field's open challenge): over-strict
  policies break real tasks; too loose and you leak. Mitigated by curated
  policies + JIT consent, but it's the hard, permanent tension.
- **Vision exfiltration:** secrets in images/canvas evade text redaction; needs
  pixel masking later.
- **Policy maintenance at scale:** sites change; the library must be kept fresh
  (this is also the moat).
- **TLS/SPA/websocket realism:** real sites are far messier than benchmark
  pages; proxy must handle streaming, SPAs, cert trust cleanly.
- **Incumbent risk:** a frontier lab bakes an equivalent in. Counter with
  vendor-neutrality + the open standard + the policy library.

---

## Sources

- OpenAI — *Continuously hardening ChatGPT Atlas against prompt injection*: https://openai.com/index/hardening-atlas-against-prompt-injection/
- CyberScoop — *OpenAI says prompt injection may never be 'solved'*: https://cyberscoop.com/openai-chatgpt-atlas-prompt-injection-browser-agent-security-update-head-of-preparedness/
- Anthropic — *Claude for Chrome*: https://www.anthropic.com/news/claude-for-chrome
- Wiz — *Agentic Browser Security: 2025 Year-End Review*: https://www.wiz.io/blog/agentic-browser-security-2025-year-end-review
- CaMeL — *Defeating Prompt Injections by Design*: https://css.csail.mit.edu/6.858/2026/readings/camel.pdf ; commentary: https://simonwillison.net/2025/apr/11/camel/
- ceLLMate — *Sandboxing Browser AI Agents*: https://cellmate-sandbox.github.io ; code: https://github.com/earlence-security/cellmate
- AgentDojo: https://arxiv.org/abs/2406.13352
- *Building Browser Agents: Architecture, Security, and Practical Solutions*: https://arxiv.org/pdf/2511.19477
- AI agent runtime security market (consolidation): https://www.straiker.ai/blog/top-7-ai-runtime-security-platforms
