# 3-Agent Incident Response System

A runnable, end-to-end incident-response pipeline for a Linux-hosted HTTP API.
Three agents collaborate over typed Pydantic handoffs to take raw logs in and a
operator-ready playbook out.

```
        nginx-access.log ──┐
        nginx-error.log  ──┼──► Agent 1 (Gemini) ──► Diagnosis ──►
        app-error.log    ──┘                                       │
                                                                   ▼
                                                  Agent 2 (deterministic
                                                   retrieval, NO LLM)
                                                                   │
                                                                   ▼
                                                          ResearchBundle
                                                                   │
                                                                   ▼
                                                  Agent 3 (Gemini) ──► Playbook
                                                                       (pre-checks /
                                                                        remediation /
                                                                        post-checks /
                                                                        rollback)
```

## Repo layout

```
.
├── main.py            # Orchestrator + 3 agents + Pydantic schemas + retrieval map
├── logs/
│   ├── nginx-access.log
│   ├── nginx-error.log
│   └── app-error.log
├── README.md
├── PROJECT_SUMMARY.md
└── SAMPLE_OUTPUT.txt  # Captured run output
```

## Prerequisites

- Python 3.10+
- `pip install pydantic google-generativeai duckduckgo-search`
  - `pydantic` is the only hard dependency.
  - `google-generativeai` is required for the live LLM path. Without it (or
    without `GEMINI_API_KEY`), the system still runs end-to-end via a
    deterministic fallback so you can demo the pipeline offline.
  - `duckduckgo-search` is optional; Agent 2 will use it for live web
    augmentation when present, and silently fall back to the curated
    documentation map when it's not.

## Configure the API key

```bash
export GEMINI_API_KEY="your-key-here"      # used by Agent 1 and Agent 3
```

The key is read with `os.getenv("GEMINI_API_KEY")` — never hardcoded.

## Run

```bash
python main.py --logs ./logs
```

Useful flags:

| Flag | Default | Purpose |
|------|---------|---------|
| `--logs DIR` | `./logs` | Directory containing the three log files |
| `--incident-id ID` | `INC-2026-04-26-001` | Stamp on the output |
| `--no-web` | off | Skip DuckDuckGo augmentation; use curated docs only |
| `--out PATH` | (none) | Also write the rendered report to a file |

Example with a saved report:

```bash
GEMINI_API_KEY=... python main.py --logs ./logs --out ./report.txt
```

## What the agents do

**Agent 1 — Log Analyst (`gemini-2.5-flash`).** Reads the three log files and
emits a JSON `Diagnosis` containing the primary cause, secondary causes, copied
verbatim evidence, short canonical `error_signatures`, affected endpoints, and
a confidence score. Output is validated against a Pydantic schema before
handoff.

**Agent 2 — Solution Researcher (deterministic, no LLM).** Walks the
`error_signatures` against a curated map of known signatures → real official
documentation URLs (Nginx, SQLAlchemy, psycopg2, Gunicorn, PostgreSQL,
PgBouncer, Linux man pages, HikariCP). When `duckduckgo-search` is installed
and `--no-web` is not set, results are augmented with live web search results.
Returns a `ResearchBundle` (the original diagnosis plus typed `DocReference`s).

**Agent 3 — Resolution Planner (`gemini-2.5-flash`).** Consumes the
`ResearchBundle` and emits a four-section operator `Playbook`: `pre_checks`,
`remediation`, `post_checks`, and `rollback`. Every step has an action, a
runnable command/check, and an expected result.

## Offline / no-API-key behavior

If `GEMINI_API_KEY` is missing or `google-generativeai` isn't installed, both
LLM agents fall back to deterministic Python heuristics that recognize the
specific signatures present in the supplied logs (SQLAlchemy QueuePool
exhaustion, psycopg2 OperationalError, gunicorn worker timeout, Nginx
`upstream timed out` / `upstream prematurely closed`, etc.) and produce the
same shape of output. This keeps the pipeline runnable for CI, demos, and
isolated environments.

## Sample output

See [`SAMPLE_OUTPUT.txt`](./SAMPLE_OUTPUT.txt) for a captured run against the
included logs. The system correctly identifies SQLAlchemy QueuePool exhaustion
driven by a session leak in deploy `2026.03.17-2`
(`portfolio/rebalance_service.py:118`), surfaces the cascade through Postgres
(`remaining connection slots are reserved`) and gunicorn (`Worker timeout`),
and produces a playbook whose first remediation step is the highest-leverage
mitigation (rollback the offending deploy).
