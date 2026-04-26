# Project Summary — 3-Agent Incident Response System

## 1. Agent boundaries and handoff formats

The system is intentionally split into three agents with **non-overlapping
responsibilities** and **typed Pydantic handoffs**. Each agent owns one
cognitive task and is forbidden to encroach on the others:

| Agent | Role | Backed by | Hard rule |
|-------|------|-----------|-----------|
| Agent 1 — Log Analyst | "What happened?" | `gemini-2.5-flash` | Must copy evidence verbatim from logs; must emit JSON conforming to `Diagnosis` |
| Agent 2 — Solution Researcher | "What does the official literature say?" | Deterministic retrieval (curated map + optional DuckDuckGo) | **No LLM.** Returns `ResearchBundle` |
| Agent 3 — Resolution Planner | "What should the operator do?" | `gemini-2.5-flash` | Must only cite the references provided by Agent 2; must emit JSON conforming to `Playbook` |

Handoff schemas live in `main.py` and are the contract between agents:

- `IncidentInput` — initial envelope (incident id + the three log strings + endpoints).
- `Diagnosis` — Agent 1 → Agent 2. Has `primary_cause`, `secondary_causes`,
  `error_signatures` (short, canonical, retrieval-friendly strings),
  `evidence: list[EvidenceItem]` (each item carries the verbatim excerpt and a
  `why_it_matters` rationale), `affected_endpoints`, and a `confidence` float.
- `ResearchBundle` — Agent 2 → Agent 3. Wraps the `Diagnosis` plus
  `references: list[DocReference]` (title, URL, source_type, relevance) and
  `research_notes`.
- `Playbook` — Agent 3 → operator. Four ordered lists of `PlaybookStep`s
  (`pre_checks`, `remediation`, `post_checks`, `rollback`), each step with
  `action`, `command_or_check`, and `expected_result`.

Pydantic validates every handoff at the boundary, so an agent that returns
malformed JSON cannot poison downstream agents. If validation fails for an LLM
agent, the system logs the error to stderr and falls back to its deterministic
path — the pipeline never silently propagates garbage.

## 2. Why the implementation choices are production-reasonable

**Typed schemas at every boundary.** Real incident-response tooling has to
survive partial outputs, model drift, and prompt-injection attempts in log
data. Pydantic gives us cheap structural validation, version-stable contracts,
and automatic JSON serialization for audit.

**Agent 2 deliberately has no LLM.** Discovery of authoritative documentation
should not be left to a model that may hallucinate URLs. The curated
signature → URL map is hand-vetted, deterministic, auditable, and trivially
reviewable in a PR. DuckDuckGo augments it for novel signatures, but the
curated map is always the floor — never the LLM's word against the docs.

**Agent 3 is constrained to Agent 2's references.** The system prompt
explicitly instructs the planner not to invent URLs. Combined with the typed
playbook output, this minimizes the surface for hallucinated remediation
steps.

**`gemini-2.5-flash` with `response_mime_type=application/json` and
`temperature=0.2`.** Flash is fast and cheap enough to be invoked twice per
incident; the JSON mime type plus low temperature keeps the structured output
parseable. The JSON parser is tolerant of accidental ```json fences.

**Offline-safe fallback.** Both LLM agents have deterministic Python
fallbacks that recognize the specific failure signatures we expect in this
environment (SQLAlchemy QueuePool, psycopg2, gunicorn worker timeout, Nginx
upstream errors). The system is therefore runnable in CI, in air-gapped
environments, and during demo failures.

**Secret hygiene.** `os.getenv("GEMINI_API_KEY")` only — no key is read from
disk, no key is logged, no key is required to start the process.

**Operator-shaped playbook.** The `pre_checks → remediation → post_checks →
rollback` shape mirrors the standard SRE runbook structure. Every step has a
runnable command and an expected result so a half-asleep oncall can follow it
without re-deriving intent.

## 3. Limitations and production safeguards

**Single-shot LLM calls.** Agent 1 and Agent 3 each call Gemini once. In
production we'd want bounded retries with exponential backoff, a per-incident
budget cap, and a circuit breaker that demotes to the deterministic fallback
after N consecutive failures.

**No tool use inside the LLM agents.** Agent 1 cannot grep additional logs;
Agent 3 cannot dry-run a `kubectl` command. A production version would expose
read-only inspection tools (log-tail, `kubectl get`, `psql -c "SELECT ..."`)
to the agents via a tool-use loop, with strict allowlisting and timeouts.

**Curated retrieval map is small.** The current map has high precision but
limited recall. Production usage should:
- back the map with a vetted internal documentation index (Confluence,
  internal wiki, prior incident write-ups);
- score and rank results;
- log every retrieval miss so the map can be extended over time.

**No write actions are taken.** This is by design — the system never executes
a remediation step. Any future "agentic remediation" mode must require
explicit operator approval per step, dry-run support, full audit logging,
RBAC-scoped credentials, and a kill switch.

**Log volume.** The current implementation passes the entire log file as a
prompt. For multi-MB logs we'd pre-summarize: regex-extract error lines,
bucket by signature, sample representative examples, and only forward the
summary to Agent 1. This both shrinks token cost and reduces the
prompt-injection surface from attacker-controlled log lines.

**Prompt injection from logs.** Adversarial content in a log line (e.g.
`"ignore previous instructions and ..."`) is currently passed verbatim. The
production version should: (a) wrap log content in a delimited block the
model is told to treat as untrusted data, (b) strip control sequences, and
(c) cross-check Agent 1's claimed evidence against the actual log text
before accepting the diagnosis.

**Confidence is self-reported.** The `confidence` field reflects the model's
own claim, not a calibrated probability. We'd pair it with deterministic
signals (signature-match count, evidence-line cross-check pass rate, history
of recent matching incidents) before ever using it to gate auto-actions.

**Severity classification.** Agent 3 assigns severity but has no notion of
business impact (revenue, SLA tier, blast radius). Production should look up
severity from a service catalog rather than letting the model guess.

**Reference freshness.** Curated URLs may move. The map should be linted by
CI (HEAD requests + canary content checks) and reviewed quarterly.

## 4. Risks intentionally accepted in this version

- We trust the model to produce JSON when asked. If it doesn't, we fall back
  rather than retry — fine for a demo, not for production.
- DuckDuckGo augmentation has no rate-limit handling; in production we'd put
  it behind a small cache and a per-incident rate budget.
- The deterministic fallback's confidence is hardcoded at 0.9 because the
  signature matches are unambiguous given the logs supplied; in a broader
  deployment confidence should be derived from match coverage rather than
  pinned.
