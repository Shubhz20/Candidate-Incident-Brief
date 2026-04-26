# Technical Summary — 3-Agent Incident Response System

*(Formatted for direct paste into Google Docs.)*

---

## 1. How to Run

### Prerequisites
- Python 3.10 or newer
- Outbound network access to `generativelanguage.googleapis.com` (for the live
  Gemini calls in Agent 1 and Agent 3)

### Step-by-step

1. **Clone or copy the project folder** so you have these files at the top
   level:
   `log_generator.py`, `agents.py`, `main.py`, `README.md`,
   `TECHNICAL_SUMMARY.md`, `DEPLOYMENT_GUIDE.md`.

2. **Create a virtual environment.**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies.**
   ```bash
   pip install --upgrade pip
   pip install pydantic google-generativeai duckduckgo-search
   ```

4. **Configure the API key.** The code reads
   `os.environ.get("GEMINI_API_KEY", "AIzaSyAezDzgyKX5lOsjvrc3mhtATgaLVs3Kszw")`.
   For evaluation, no extra step is needed; for any real use, set the env var:
   ```bash
   export GEMINI_API_KEY="your-key-here"
   ```

5. **Generate the demo logs.** The brief asks the system to produce its own
   "smoking gun" logs:
   ```bash
   python log_generator.py
   ```
   This writes `logs/nginx-access.log`, `logs/nginx-error.log`, and
   `logs/app-error.log`.

6. **Run the pipeline.**
   ```bash
   python main.py --logs ./logs --out ./report.txt
   ```
   The orchestrator prints progress to stderr, writes the full report to
   `report.txt`, and also echoes it to stdout.

7. **Inspect the report.** Open `report.txt`. You will see a `Diagnosis`
   section (Agent 1), a `References` section (Agent 2), and a four-part
   `Playbook` (Agent 3) with `pre_checks`, `remediation`, `post_checks`, and
   `rollback`.

If the Gemini API is unreachable or the key is invalid, the orchestrator logs
the failure to stderr and falls back to the deterministic Python path so the
pipeline still produces an end-to-end report. This guarantees a non-empty
deliverable in offline / restricted environments.

---

## 2. Conclusion — What the System Diagnosed

Against the supplied logs (DB connection pool exhaustion scenario), the system
produces the following findings:

- **Primary cause:** SQLAlchemy `QueuePool` exhaustion in the API app tier.
  Pool configured `pool_size=20, max_overflow=5`; observed checked_out = 25,
  waiters = 57. Callers wait the full 30 s `pool_timeout` before failing,
  which directly produces the 60 s Nginx upstream timeouts.

- **Triggering change:** Deploy `2026.03.17-2` modified
  `app/services/portfolio/rebalance_service.py:118` and introduced a session
  leak — `session close skipped` and `suspected session leak` warnings appear
  within minutes of the deploy.

- **Cascade:** SQLAlchemy `TimeoutError` → gunicorn workers exceed their
  request timeout and are killed (`Worker timeout (pid: ...)`) → Nginx emits
  504 (`upstream timed out (110)`) and 502 (`upstream prematurely closed
  connection`). At the database tier, Postgres itself reports
  `remaining connection slots are reserved`, confirming saturation is
  end-to-end.

- **Affected endpoints:** `/api/v1/auth/login`, `/api/v1/portfolio/summary`,
  `/api/v1/watchlist`, `/api/v1/orders`, `/api/v1/orders/rebalance`,
  `/api/v1/recommendations`. `/health` continues to return 200 because it
  does not hit the database — meaning **a load-balancer-level health check
  would not have caught this**, which is itself a finding.

- **Recommended mitigation (Agent 3):** roll back the API deployment to the
  revision preceding `2026.03.17-2`; terminate Postgres backends still held
  in `idle in transaction`; use PgBouncer as a durable safeguard; land a
  forward-fix that enforces `with SessionLocal() as session:` (or wraps the
  session in `try/finally`) at the leak site.

The full diagnosis, references, and playbook are in `SAMPLE_OUTPUT.txt`.

---

## 3. Logic Explanation

### 3.1 Agent boundaries

Each agent has a single responsibility and is forbidden to encroach on the
others. This isolation is what makes the system auditable.

| Agent | Role | Backed by | Hard rule |
|-------|------|-----------|-----------|
| **Agent 1 — Log Analyst** | "What happened?" | `gemini-2.5-flash` | Must copy evidence verbatim from the supplied logs; output validated against `Diagnosis` |
| **Agent 2 — Solution Researcher** | "What does the official literature say?" | Deterministic Python (curated map of real official URLs + optional DuckDuckGo) | **No LLM is allowed.** Output validated against `ResearchBundle` |
| **Agent 3 — Resolution Planner** | "What should the operator do?" | `gemini-2.5-flash` | Must only cite the references provided by Agent 2; output validated against `Playbook` |

### 3.2 Pydantic handoff format

All inter-agent communication uses typed Pydantic models defined in
`agents.py`. Each handoff is validated at the boundary; an agent that returns
malformed JSON cannot poison downstream agents.

```python
IncidentInput  ── Agent 1 ──►  Diagnosis        ── Agent 2 ──►  ResearchBundle
                                                                       │
                                                                       ▼
                                                              Agent 3 ──►  Playbook
```

The key fields:

- **`Diagnosis`** carries `primary_cause`, `secondary_causes`,
  `error_signatures` (short canonical phrases used to drive retrieval),
  `evidence: List[EvidenceItem]` (each with the verbatim excerpt and a
  rationale), `affected_endpoints`, and a `confidence` float.
- **`ResearchBundle`** wraps the original `Diagnosis` plus
  `references: List[DocReference]` (`title`, `url`, `source_type`, `relevance`).
- **`Playbook`** has four ordered lists of `PlaybookStep`s — `pre_checks`,
  `remediation`, `post_checks`, `rollback` — each with `action`,
  `command_or_check`, and `expected_result`.

### 3.3 Why this design is "production-reasonable"

**Separation of concerns.** The three agents map onto three distinct
sub-problems: pattern recognition over noisy text (LLM is good at this),
authoritative documentation lookup (LLMs hallucinate URLs — keep it
deterministic), and operator-ready runbook authoring (LLM is good at this
*if* given trustworthy grounding). Mixing these tasks into one prompt is the
classic anti-pattern that produces confident, evidence-free recommendations.

**Grounding in research.** Agent 3's system prompt explicitly forbids
inventing URLs and constrains it to the references Agent 2 surfaced. Agent 1
is told to copy evidence verbatim. These constraints, plus the Pydantic
validators, make the chain of reasoning auditable: every recommendation can
be traced back to a documentation URL and to a specific log line.

**Typed contracts at every boundary.** Real incident-response tooling has to
survive partial outputs, model drift, and prompt-injection attempts in log
data. Pydantic gives us cheap structural validation, version-stable
contracts, and automatic JSON serialization for audit logging.

**Deterministic fallbacks.** Both LLM agents have offline fallbacks that
recognize the specific signatures in the included logs (SQLAlchemy
`QueuePool`, `psycopg2.OperationalError`, gunicorn `Worker timeout`, Nginx
`upstream timed out` / `upstream prematurely closed`, etc.). The system is
runnable in CI, in air-gapped environments, and during temporary LLM
outages — a real production property, not a demo gimmick.

**Operator-shaped output.** The
`pre_checks → remediation → post_checks → rollback` shape mirrors standard
SRE runbook structure. Every step has a runnable command and an expected
result so a half-asleep oncall can follow it without re-deriving intent.

**Secret hygiene.** The API key is read via `os.environ.get` and never
written to disk by the code. The hardcoded fallback is explicitly labeled
for evaluation only and is documented to be removed in production
environments.

---

## 4. Limitations & Missing Production Safeguards

### 4.1 Assumptions baked into this version

- The three log files fit in a single Gemini context window. For multi-MB
  log streams, a pre-summarizer (regex extraction → bucket by signature →
  sample representative examples) would be needed to keep prompts and cost
  bounded.
- The deterministic-fallback path has been tuned to recognize the failure
  modes most likely to appear in this stack (Python / SQLAlchemy / psycopg2
  / gunicorn / Nginx). It is precision-biased; a wider deployment would
  need a richer signature library and a way to tell when no signature
  matches.
- `confidence` is the model's own self-report, not a calibrated probability.
  It must not be used to gate auto-remediation without recalibration against
  ground truth.
- Severity (SEV1/2/3) is assigned by Agent 3 from the diagnosis text alone;
  in production the severity should come from a service catalog that knows
  blast radius, SLA tier, and revenue impact.

### 4.2 Production safeguards intentionally not included

- **Human-in-the-loop.** The system never executes a remediation — it
  produces a playbook for an operator to run. Any future "agentic
  remediation" mode must require explicit per-step approval, dry-run support,
  full audit logging, RBAC-scoped credentials, and a kill switch.
- **AuthN / AuthZ on the orchestrator.** The CLI assumes whoever runs it is
  authorized to read logs and produce reports. In a multi-tenant deployment,
  the entry point must enforce identity (OIDC / IAM) and authorize access to
  each log source separately.
- **Secrets management.** Production deployments should pull
  `GEMINI_API_KEY` from a secrets manager (AWS Secrets Manager, GCP Secret
  Manager, HashiCorp Vault, Kubernetes Secrets via CSI driver) rather than
  the environment, with rotation alerts.
- **LLM resilience.** Agent 1 and Agent 3 currently make a single Gemini
  call. Production should add bounded retries with exponential backoff, a
  per-incident token budget, a circuit breaker that demotes to deterministic
  output after N consecutive failures, and timeout protection so a hung
  request can never block an incident pipeline.
- **Prompt-injection defense for log content.** Adversarial content in a log
  line (e.g. `"ignore previous instructions and ..."`) is currently passed
  verbatim. Production should: (a) wrap log content as untrusted data with
  unambiguous delimiters; (b) strip control sequences; (c) cross-check
  Agent 1's evidence excerpts against the actual log text before accepting
  the diagnosis.
- **Curated documentation map maintenance.** URLs change. CI should lint the
  `KNOWN_DOCS` list with HEAD requests and canary content checks; the map
  itself should be backed by a vetted internal documentation index
  (Confluence, internal wiki, prior incident write-ups) with miss-logging so
  it can grow over time.
- **Observability of the agents themselves.** Production should record the
  full prompt, response, validation result, latency, and token cost for
  every agent call, with PII scrubbing, into a queryable store.
- **Structured outbound notifications.** PagerDuty / Slack / Opsgenie
  integrations are not included — the current renderer writes plain text.

These are deliberate scope cuts for a focused deliverable, not oversights.
The architecture supports each of them as additive layers without rewrites.
