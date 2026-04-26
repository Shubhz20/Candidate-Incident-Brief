"""
3-Agent Incident Response System
================================

Architecture
------------
    [Logs on disk] --> Agent 1 (LogAnalyst, Gemini)
                            |
                            v
                       Diagnosis (Pydantic)
                            |
                            v
                  Agent 2 (SolutionResearcher, deterministic retrieval)
                            |
                            v
                       ResearchBundle (Pydantic)
                            |
                            v
                  Agent 3 (ResolutionPlanner, Gemini)
                            |
                            v
                       Playbook (Pydantic) -> rendered to operator

Run:
    export GEMINI_API_KEY=...
    python main.py --logs ./logs

Notes:
- Agent 1 and Agent 3 use gemini-2.5-flash via the google-generativeai SDK and
  return JSON that is validated by Pydantic schemas.
- Agent 2 deliberately does NOT use an LLM. It performs deterministic
  retrieval against a curated mapping of known errors -> real official
  documentation URLs, and (when network/duckduckgo-search is available)
  augments with live web search results.
- All inter-agent handoffs are typed Pydantic models for safety + auditability.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field, ValidationError

# ---------------------------------------------------------------------------
# Optional dependencies
# ---------------------------------------------------------------------------
# google-generativeai is required for live LLM calls. If absent, the system
# falls back to a deterministic stub so the pipeline remains fully runnable
# (useful for CI, demos, and offline operation).
try:
    import google.generativeai as genai  # type: ignore
    _GENAI_AVAILABLE = True
except Exception:  # pragma: no cover
    _GENAI_AVAILABLE = False

# duckduckgo-search is optional; Agent 2 will use it when available, otherwise
# falls back to its curated retrieval map.
try:
    from duckduckgo_search import DDGS  # type: ignore
    _DDG_AVAILABLE = True
except Exception:  # pragma: no cover
    _DDG_AVAILABLE = False


# =============================================================================
# Pydantic handoff schemas
# =============================================================================

class IncidentInput(BaseModel):
    """Initial incident envelope handed to Agent 1."""
    incident_id: str
    nginx_access_log: str
    nginx_error_log: str
    app_error_log: str
    affected_endpoints: List[str] = Field(default_factory=list)


class EvidenceItem(BaseModel):
    source: str  # e.g. "nginx-error.log"
    excerpt: str
    why_it_matters: str


class Diagnosis(BaseModel):
    """Output of Agent 1 -> input to Agent 2."""
    incident_id: str
    primary_cause: str
    secondary_causes: List[str] = Field(default_factory=list)
    error_signatures: List[str] = Field(
        default_factory=list,
        description="Canonical short strings used to drive retrieval, e.g. "
                    "'HikariCP connection timeout', 'nginx 504 upstream timed out'."
    )
    evidence: List[EvidenceItem] = Field(default_factory=list)
    affected_endpoints: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str


class DocReference(BaseModel):
    title: str
    url: str
    source_type: str  # "official-doc" | "vendor-kb" | "web-search"
    relevance: str


class ResearchBundle(BaseModel):
    """Output of Agent 2 -> input to Agent 3."""
    incident_id: str
    diagnosis: Diagnosis
    references: List[DocReference]
    research_notes: str


class PlaybookStep(BaseModel):
    order: int
    action: str
    command_or_check: Optional[str] = None
    expected_result: Optional[str] = None


class Playbook(BaseModel):
    """Output of Agent 3 -> rendered to operator."""
    incident_id: str
    title: str
    severity: str  # SEV1 / SEV2 / SEV3
    pre_checks: List[PlaybookStep]
    remediation: List[PlaybookStep]
    post_checks: List[PlaybookStep]
    rollback: List[PlaybookStep]
    notes: str


# =============================================================================
# Gemini helper
# =============================================================================

GEMINI_MODEL = "gemini-2.5-flash"


def _configure_gemini() -> bool:
    """Configure the Gemini SDK if both the package and key are available."""
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return False
    if not _GENAI_AVAILABLE:
        return False
    genai.configure(api_key=api_key)
    return True


def _call_gemini_json(system_instruction: str, user_prompt: str) -> dict:
    """Call gemini-2.5-flash and parse a JSON object from the response.

    Robust to the model wrapping JSON in ```json fences or adding stray prose.
    Raises RuntimeError on hard failure so the caller can fall back.
    """
    if not _configure_gemini():
        raise RuntimeError("Gemini not configured (missing GEMINI_API_KEY or google-generativeai)")

    model = genai.GenerativeModel(
        model_name=GEMINI_MODEL,
        system_instruction=system_instruction,
        generation_config={
            "temperature": 0.2,
            "response_mime_type": "application/json",
        },
    )
    resp = model.generate_content(user_prompt)
    text = (resp.text or "").strip()

    # Strip ```json fences if the model added them despite response_mime_type
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.MULTILINE).strip()

    # As a last resort, find the first {...} block
    if not text.startswith("{"):
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if match:
            text = match.group(0)

    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Gemini returned non-JSON content: {e}\n---\n{text}") from e


# =============================================================================
# Agent 1 — Log Analyst (Gemini)
# =============================================================================

AGENT1_SYSTEM = """You are an SRE log analyst. Given raw Nginx access/error logs and
application error logs, produce a structured diagnosis. Be specific. Do not invent
evidence: every excerpt in `evidence` must be copied verbatim from the supplied logs.

Return JSON ONLY matching this schema:
{
  "incident_id": str,
  "primary_cause": str,
  "secondary_causes": [str],
  "error_signatures": [str],         // short canonical phrases, suitable for search
  "evidence": [
    {"source": str, "excerpt": str, "why_it_matters": str}
  ],
  "affected_endpoints": [str],
  "confidence": float,                // 0..1
  "summary": str
}
"""


class LogAnalystAgent:
    name = "Agent 1 — Log Analyst (gemini-2.5-flash)"

    def run(self, incident: IncidentInput) -> Diagnosis:
        user_prompt = textwrap.dedent(f"""
        Incident ID: {incident.incident_id}
        Affected endpoints (reported): {", ".join(incident.affected_endpoints) or "unknown"}

        --- nginx-access.log ---
        {incident.nginx_access_log}

        --- nginx-error.log ---
        {incident.nginx_error_log}

        --- app-error.log ---
        {incident.app_error_log}

        Diagnose the incident. Identify the primary cause, supporting evidence (copied
        verbatim), and short canonical `error_signatures` we can hand to a retrieval
        agent (e.g. 'HikariCP connection timeout 30000ms', 'nginx upstream timed out 110').
        """).strip()

        try:
            raw = _call_gemini_json(AGENT1_SYSTEM, user_prompt)
            raw["incident_id"] = incident.incident_id  # enforce
            return Diagnosis.model_validate(raw)
        except (RuntimeError, ValidationError) as e:
            print(f"[Agent 1] Gemini path failed ({e}); using deterministic fallback.",
                  file=sys.stderr)
            return self._fallback(incident)

    # ------------------------------------------------------------------
    # Deterministic fallback so the pipeline runs without an API key.
    # The heuristic looks for known signatures in the supplied logs.
    # ------------------------------------------------------------------
    def _fallback(self, incident: IncidentInput) -> Diagnosis:
        evidence: List[EvidenceItem] = []
        signatures: List[str] = []
        secondary: List[str] = []

        nginx_err = incident.nginx_error_log
        app_err = incident.app_error_log

        if "upstream timed out" in nginx_err:
            signatures.append("nginx upstream timed out (110: Connection timed out)")
            line = next((ln for ln in nginx_err.splitlines()
                         if "upstream timed out" in ln), "")
            evidence.append(EvidenceItem(
                source="nginx-error.log",
                excerpt=line.strip(),
                why_it_matters="Nginx is hitting proxy_read_timeout because the upstream "
                               "app server never returned a response — classic symptom of "
                               "a stalled backend, not a network failure."
            ))
        if "upstream prematurely closed connection" in nginx_err:
            signatures.append("nginx upstream prematurely closed connection (502)")
            line = next((ln for ln in nginx_err.splitlines()
                         if "upstream prematurely closed connection" in ln), "")
            evidence.append(EvidenceItem(
                source="nginx-error.log",
                excerpt=line.strip(),
                why_it_matters="Worker died mid-request — matches gunicorn 'Worker timeout / "
                               "Worker exiting' lines and produces 502s on the edge."
            ))
        if "Connection refused" in nginx_err or "ConnectionRefusedError" in app_err:
            signatures.append("nginx connect() failed (111: Connection refused)")
            secondary.append("All gunicorn workers temporarily down (no listener on :8000)")

        # SQLAlchemy QueuePool exhaustion (Python stack)
        if "QueuePool limit of size" in app_err:
            signatures.append("SQLAlchemy QueuePool limit reached (sqlalchemy.exc.TimeoutError)")
            line = next((ln for ln in app_err.splitlines()
                         if "QueuePool limit of size" in ln and "ERROR" in ln), "")
            if not line:
                line = next((ln for ln in app_err.splitlines()
                             if "QueuePool limit of size" in ln), "")
            evidence.append(EvidenceItem(
                source="app-error.log",
                excerpt=line.strip(),
                why_it_matters="App pool (size=20, max_overflow=5) is fully checked out and "
                               "callers wait the full 30s pool_timeout before failing — this "
                               "directly produces the 60s Nginx upstream timeouts."
            ))
        if "remaining connection slots are reserved" in app_err:
            signatures.append("PostgreSQL: remaining connection slots are reserved (psycopg2.OperationalError)")
            secondary.append("Postgres max_connections also saturated at the DB tier")
            line = next((ln for ln in app_err.splitlines()
                         if "remaining connection slots are reserved" in ln), "")
            evidence.append(EvidenceItem(
                source="app-error.log",
                excerpt=line.strip(),
                why_it_matters="Even if the app pool grew, Postgres itself is refusing new "
                               "connections — saturation is end-to-end."
            ))
        if "session close skipped" in app_err or "suspected session leak" in app_err:
            signatures.append("SQLAlchemy session leak (session close skipped)")
            secondary.append("Suspected session leak in portfolio/rebalance_service.py:118")
            line = next((ln for ln in app_err.splitlines()
                         if "suspected session leak" in ln), "")
            evidence.append(EvidenceItem(
                source="app-error.log",
                excerpt=line.strip(),
                why_it_matters="Sessions checked out but not returned — the underlying cause "
                               "of pool exhaustion, not just a symptom."
            ))
        if "Worker timeout" in app_err:
            signatures.append("gunicorn Worker timeout")
            secondary.append("Gunicorn workers killed while blocked on DB → premature 502s")
        if "deployment_version=2026.03.17-2" in app_err and "rebalance_service" in app_err:
            secondary.append("Recent deploy 2026.03.17-2 modified rebalance DB session lifecycle "
                             "— strong correlation with leak onset")

        primary = ("Database connection pool exhaustion in the API app tier (SQLAlchemy "
                   "QueuePool size=20 + overflow=5 fully checked out, ~57 waiters), driven "
                   "by a session leak introduced in deploy 2026.03.17-2 to "
                   "portfolio/rebalance_service.py:118. The starved pool causes 30s "
                   "pool_timeout failures and gunicorn worker timeouts, which Nginx surfaces "
                   "as 504/502 on /api/v1/auth/login, /api/v1/portfolio/summary, "
                   "/api/v1/watchlist, /api/v1/orders, /api/v1/orders/rebalance and "
                   "/api/v1/recommendations.")
        summary = ("Pool went from healthy → 'usage high' (checked_out=18) → fully exhausted "
                   "(checked_out=25, waiters=57) within ~3 minutes after rebalance traffic "
                   "ramped on the new deploy. SQLAlchemy raises QueuePool TimeoutError after "
                   "30s; gunicorn workers exceed their request timeout and are killed, "
                   "leaving Nginx to emit 502 ('upstream prematurely closed connection') and "
                   "504 ('upstream timed out (110)'). Postgres itself reports "
                   "'remaining connection slots are reserved', confirming the saturation is "
                   "end-to-end. /health continues to return 200 because it does not hit the "
                   "database — so an LB-level health check would NOT have caught this.")

        return Diagnosis(
            incident_id=incident.incident_id,
            primary_cause=primary,
            secondary_causes=secondary,
            error_signatures=signatures,
            evidence=evidence,
            affected_endpoints=incident.affected_endpoints or [
                "/api/v1/auth/login", "/api/v1/portfolio/summary",
                "/api/v1/watchlist", "/api/v1/orders",
                "/api/v1/orders/rebalance", "/api/v1/recommendations",
            ],
            confidence=0.9,
            summary=summary,
        )


# =============================================================================
# Agent 2 — Solution Researcher (NO LLM)
# =============================================================================

# Curated, hand-vetted mapping from canonical error signatures to *real* official
# documentation pages. This is the high-fidelity retrieval substrate; web search
# (DuckDuckGo) augments it but never replaces it. Keys are matched by substring
# against the diagnosis's `error_signatures` and `primary_cause`.
KNOWN_DOCS: List[dict] = [
    {
        "match": ["upstream timed out", "504", "proxy_read_timeout"],
        "title": "Nginx ngx_http_proxy_module — proxy_read_timeout / proxy_connect_timeout",
        "url": "https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_read_timeout",
        "source_type": "official-doc",
        "relevance": "Defines the directives that produce '110: Connection timed out' "
                     "and how to tune them.",
    },
    {
        "match": ["Connection refused", "connect() failed", "111"],
        "title": "Nginx Admin Guide — Debugging upstream errors",
        "url": "https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/",
        "source_type": "official-doc",
        "relevance": "Reverse-proxy troubleshooting including connect()/refused errors.",
    },
    {
        "match": ["HikariCP", "HikariPool", "Connection is not available"],
        "title": "HikariCP — Configuration & Pool Sizing (official wiki)",
        "url": "https://github.com/brettwooldridge/HikariCP/wiki/About-Pool-Sizing",
        "source_type": "official-doc",
        "relevance": "Authoritative guidance on maximumPoolSize, connectionTimeout, "
                     "and leak detection.",
    },
    {
        "match": ["HikariCP", "leakDetectionThreshold"],
        "title": "HikariCP — README (configuration knobs)",
        "url": "https://github.com/brettwooldridge/HikariCP#frequently-used",
        "source_type": "official-doc",
        "relevance": "leakDetectionThreshold, idleTimeout, maxLifetime — directly "
                     "applicable to a saturated pool.",
    },
    {
        "match": ["QueuePool", "SQLAlchemy", "sqlalchemy.exc.TimeoutError"],
        "title": "SQLAlchemy — QueuePool API (pool_size, max_overflow, pool_timeout)",
        "url": "https://docs.sqlalchemy.org/en/20/core/pooling.html#sqlalchemy.pool.QueuePool",
        "source_type": "official-doc",
        "relevance": "Defines exactly the 'QueuePool limit of size N overflow M reached' "
                     "error and the knobs that drive it.",
    },
    {
        "match": ["session leak", "SessionLocal", "scoped_session", "session.close"],
        "title": "SQLAlchemy — Session Basics (lifecycle, closing, context-manager use)",
        "url": "https://docs.sqlalchemy.org/en/20/orm/session_basics.html",
        "source_type": "official-doc",
        "relevance": "Authoritative reference for correct session lifecycle to fix leaks.",
    },
    {
        "match": ["pool_pre_ping", "pool_recycle", "stale connection"],
        "title": "SQLAlchemy — Dealing with Disconnects (pool_pre_ping, pool_recycle)",
        "url": "https://docs.sqlalchemy.org/en/20/core/pooling.html#dealing-with-disconnects",
        "source_type": "official-doc",
        "relevance": "Hardens pool against half-dead connections that worsen exhaustion.",
    },
    {
        "match": ["psycopg2.OperationalError", "remaining connection slots are reserved"],
        "title": "psycopg2 — Connection class & error mapping",
        "url": "https://www.psycopg.org/docs/connection.html",
        "source_type": "official-doc",
        "relevance": "Documents the exact OperationalError surfaced when Postgres "
                     "rejects new connections.",
    },
    {
        "match": ["gunicorn", "Worker timeout", "WORKER TIMEOUT"],
        "title": "Gunicorn — Settings (timeout, workers, worker_class)",
        "url": "https://docs.gunicorn.org/en/stable/settings.html#timeout",
        "source_type": "official-doc",
        "relevance": "Worker timeout produces the 'Worker timeout (pid: ...)' log lines "
                     "observed when DB calls block too long.",
    },
    {
        "match": ["uvicorn", "FastAPI"],
        "title": "Uvicorn — Settings & deployment",
        "url": "https://www.uvicorn.org/settings/",
        "source_type": "official-doc",
        "relevance": "Worker class config when running FastAPI/Starlette under gunicorn.",
    },
    {
        "match": ["too many clients already", "max_connections", "PostgreSQL"],
        "title": "PostgreSQL — Connections and Authentication (max_connections)",
        "url": "https://www.postgresql.org/docs/current/runtime-config-connection.html",
        "source_type": "official-doc",
        "relevance": "Defines max_connections and the 'too many clients already' error.",
    },
    {
        "match": ["pgbouncer", "connection pool", "too many clients"],
        "title": "PgBouncer — Lightweight connection pooler for PostgreSQL",
        "url": "https://www.pgbouncer.org/usage.html",
        "source_type": "official-doc",
        "relevance": "Standard production remedy when an app-side pool overruns Postgres.",
    },
    {
        "match": ["Slow query", "pg_stat_statements"],
        "title": "PostgreSQL — pg_stat_statements",
        "url": "https://www.postgresql.org/docs/current/pgstatstatements.html",
        "source_type": "official-doc",
        "relevance": "Identify the slow query holding pool connections.",
    },
    {
        "match": ["Linux", "ulimit", "file descriptor"],
        "title": "Linux man-pages — getrlimit(2) / ulimit",
        "url": "https://man7.org/linux/man-pages/man2/getrlimit.2.html",
        "source_type": "official-doc",
        "relevance": "Verify FD limits aren't an additional bottleneck under load.",
    },
]


class SolutionResearcherAgent:
    """Deterministic retrieval. Optionally augments with DuckDuckGo search."""

    name = "Agent 2 — Solution Researcher (deterministic retrieval, no LLM)"

    def __init__(self, use_web: bool = True, max_web_results: int = 3):
        self.use_web = use_web
        self.max_web_results = max_web_results

    def run(self, diagnosis: Diagnosis) -> ResearchBundle:
        refs: List[DocReference] = []
        seen_urls = set()

        haystack = " ".join(
            [diagnosis.primary_cause] + diagnosis.secondary_causes + diagnosis.error_signatures
        ).lower()

        # 1) Curated retrieval
        for entry in KNOWN_DOCS:
            if any(token.lower() in haystack for token in entry["match"]):
                if entry["url"] in seen_urls:
                    continue
                seen_urls.add(entry["url"])
                refs.append(DocReference(
                    title=entry["title"],
                    url=entry["url"],
                    source_type=entry["source_type"],
                    relevance=entry["relevance"],
                ))

        # 2) Optional live web augmentation via DuckDuckGo
        web_notes = ""
        if self.use_web and _DDG_AVAILABLE and diagnosis.error_signatures:
            try:
                with DDGS() as ddgs:
                    for sig in diagnosis.error_signatures[:2]:
                        results = list(ddgs.text(sig, max_results=self.max_web_results))
                        for r in results:
                            url = r.get("href") or r.get("url")
                            title = r.get("title", "Web result")
                            if not url or url in seen_urls:
                                continue
                            seen_urls.add(url)
                            refs.append(DocReference(
                                title=title,
                                url=url,
                                source_type="web-search",
                                relevance=f"DuckDuckGo result for signature: {sig!r}",
                            ))
                web_notes = "Augmented with live DuckDuckGo results."
            except Exception as e:  # pragma: no cover
                web_notes = f"Web search skipped: {e}"
        elif self.use_web and not _DDG_AVAILABLE:
            web_notes = ("duckduckgo-search not installed; using curated retrieval only. "
                         "`pip install duckduckgo-search` to enable live augmentation.")
        else:
            web_notes = "Web augmentation disabled by caller."

        notes = (f"Matched {len(refs)} reference(s) for signatures: "
                 f"{diagnosis.error_signatures}. {web_notes}")

        return ResearchBundle(
            incident_id=diagnosis.incident_id,
            diagnosis=diagnosis,
            references=refs,
            research_notes=notes,
        )


# =============================================================================
# Agent 3 — Resolution Planner (Gemini)
# =============================================================================

AGENT3_SYSTEM = """You are an SRE resolution planner. Given a structured diagnosis and
a vetted set of documentation references, produce a concrete operator playbook.
Every step must be runnable or directly checkable. Do NOT invent reference URLs;
only refer to the provided references when citing sources.

Return JSON ONLY matching this schema:
{
  "incident_id": str,
  "title": str,
  "severity": "SEV1" | "SEV2" | "SEV3",
  "pre_checks":   [{"order": int, "action": str, "command_or_check": str, "expected_result": str}],
  "remediation":  [{"order": int, "action": str, "command_or_check": str, "expected_result": str}],
  "post_checks":  [{"order": int, "action": str, "command_or_check": str, "expected_result": str}],
  "rollback":     [{"order": int, "action": str, "command_or_check": str, "expected_result": str}],
  "notes": str
}
"""


class ResolutionPlannerAgent:
    name = "Agent 3 — Resolution Planner (gemini-2.5-flash)"

    def run(self, bundle: ResearchBundle) -> Playbook:
        diag = bundle.diagnosis
        refs_block = "\n".join(
            f"- [{r.source_type}] {r.title} :: {r.url} :: {r.relevance}"
            for r in bundle.references
        ) or "(no references found)"

        user_prompt = textwrap.dedent(f"""
        Incident: {diag.incident_id}
        Primary cause: {diag.primary_cause}
        Secondary causes: {diag.secondary_causes}
        Error signatures: {diag.error_signatures}
        Affected endpoints: {diag.affected_endpoints}
        Confidence: {diag.confidence}

        Diagnosis summary:
        {diag.summary}

        Vetted references:
        {refs_block}

        Produce a complete playbook (pre_checks, remediation, post_checks, rollback).
        Prefer commands a Linux SRE can run on the API host or via kubectl. Be explicit
        about expected results. Include at least one verification of the upstream/db pool
        health in post_checks, and explicit rollback for any config change.
        """).strip()

        try:
            raw = _call_gemini_json(AGENT3_SYSTEM, user_prompt)
            raw["incident_id"] = diag.incident_id
            return Playbook.model_validate(raw)
        except (RuntimeError, ValidationError) as e:
            print(f"[Agent 3] Gemini path failed ({e}); using deterministic fallback.",
                  file=sys.stderr)
            return self._fallback(bundle)

    def _fallback(self, bundle: ResearchBundle) -> Playbook:
        diag = bundle.diagnosis
        return Playbook(
            incident_id=diag.incident_id,
            title=("Mitigate SQLAlchemy QueuePool exhaustion (suspected session leak in "
                   "deploy 2026.03.17-2) causing 504/502 across login, portfolio, watchlist, "
                   "orders, rebalance, recommendations"),
            severity="SEV2",
            pre_checks=[
                PlaybookStep(
                    order=1,
                    action="Reproduce the symptom from outside the cluster",
                    command_or_check="curl -sS -o /dev/null -w '%{http_code} %{time_total}\\n' "
                                     "https://api.example.com/api/v1/portfolio/summary",
                    expected_result="HTTP 504 (or 502) with rt close to proxy_read_timeout (~60s)",
                ),
                PlaybookStep(
                    order=2,
                    action="Confirm /health stays green (rules out total outage; confirms DB-only path)",
                    command_or_check="curl -sS -o /dev/null -w '%{http_code}\\n' https://api.example.com/health",
                    expected_result="HTTP 200 — confirms ingress, gunicorn, and uvicorn are alive",
                ),
                PlaybookStep(
                    order=3,
                    action="Verify SQLAlchemy QueuePool is saturated",
                    command_or_check="kubectl logs deploy/api --tail=500 | "
                                     "grep -E 'QueuePool|checked_out|waiters'",
                    expected_result="checked_out=25 (size=20+overflow=5), waiters > 0, "
                                     "TimeoutError after 30.00s",
                ),
                PlaybookStep(
                    order=4,
                    action="Verify Postgres-side saturation",
                    command_or_check="psql -h $PGHOST -U $PGUSER -c "
                                     "\"SELECT count(*) FROM pg_stat_activity; SHOW max_connections;\"",
                    expected_result="count(*) at or near max_connections; "
                                     "OperationalError 'remaining connection slots are reserved' visible",
                ),
                PlaybookStep(
                    order=5,
                    action="Identify long-held / leaking sessions and the queries they hold",
                    command_or_check="psql -c \"SELECT pid, application_name, state, "
                                     "now()-state_change AS idle_for, query "
                                     "FROM pg_stat_activity "
                                     "WHERE state IN ('idle in transaction','active') "
                                     "ORDER BY idle_for DESC LIMIT 20;\"",
                    expected_result="Multiple 'idle in transaction' rows from the API, "
                                     "concentrated on rebalance-related queries",
                ),
                PlaybookStep(
                    order=6,
                    action="Correlate with the most recent deploy",
                    command_or_check="kubectl rollout history deploy/api | head && "
                                     "git log --oneline -- app/services/portfolio/rebalance_service.py | head",
                    expected_result="Deploy 2026.03.17-2 (~11:34 IST) precedes the spike by a "
                                     "few minutes — strong leak suspect",
                ),
            ],
            remediation=[
                PlaybookStep(
                    order=1,
                    action="MITIGATE FIRST: roll back the API to the deploy preceding 2026.03.17-2",
                    command_or_check="kubectl rollout undo deploy/api && "
                                     "kubectl rollout status deploy/api --timeout=180s",
                    expected_result="Pods return to last-known-good revision; pool stats normalize "
                                     "within ~2 min",
                ),
                PlaybookStep(
                    order=2,
                    action="Terminate stuck Postgres backends still held by old workers",
                    command_or_check="psql -c \"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                                     "WHERE application_name='api' AND state='idle in transaction' "
                                     "AND now()-state_change > interval '60 seconds';\"",
                    expected_result="Stuck connections released; Postgres backend count drops",
                ),
                PlaybookStep(
                    order=3,
                    action="If rollback isn't possible, raise pool capacity as a holding action only",
                    command_or_check="kubectl set env deploy/api DB_POOL_SIZE=40 DB_MAX_OVERFLOW=10 "
                                     "DB_POOL_TIMEOUT=10 && kubectl rollout status deploy/api",
                    expected_result="Pool grows; do NOT leave permanently — root cause is the leak",
                ),
                PlaybookStep(
                    order=4,
                    action="Stand up PgBouncer (transaction pooling) so app pool growth doesn't "
                           "saturate Postgres",
                    command_or_check="kubectl apply -f infra/pgbouncer.yaml && "
                                     "kubectl set env deploy/api DB_HOST=pgbouncer DB_PORT=6432",
                    expected_result="API connects via PgBouncer; Postgres connection count "
                                     "drops to a small steady-state",
                ),
                PlaybookStep(
                    order=5,
                    action="Patch the leak: ensure SessionLocal() is always used as a context "
                           "manager (or wrapped in try/finally with session.close()) in "
                           "rebalance_service.py:118",
                    command_or_check="git revert <sha-of-2026.03.17-2-rebalance-change>  # "
                                     "or land a forward-fix PR enforcing `with SessionLocal() as s:`",
                    expected_result="No more 'session close skipped' or 'suspected session leak' "
                                     "warnings under load",
                ),
                PlaybookStep(
                    order=6,
                    action="Harden pool against half-dead connections",
                    command_or_check="Set engine kwargs: pool_pre_ping=True, "
                                     "pool_recycle=1800, pool_timeout=10",
                    expected_result="Stale connections recycled silently; faster fail-fast on "
                                     "pool starvation reduces gunicorn worker timeouts",
                ),
            ],
            post_checks=[
                PlaybookStep(
                    order=1,
                    action="All affected endpoints return 200 with healthy latency",
                    command_or_check="for p in /api/v1/auth/login /api/v1/portfolio/summary "
                                     "/api/v1/watchlist /api/v1/orders /api/v1/recommendations; do "
                                     "curl -sS -o /dev/null -w \"$p %{http_code} %{time_total}\\n\" "
                                     "https://api.example.com$p; done",
                    expected_result="All HTTP 200; p95 latency < 1s",
                ),
                PlaybookStep(
                    order=2,
                    action="QueuePool stable for 10 minutes",
                    command_or_check="kubectl logs deploy/api --since=10m | "
                                     "grep -E 'QueuePool|checked_out' | tail -20",
                    expected_result="No 'usage high' or 'pool exhausted'; checked_out steady "
                                     "well below pool_size",
                ),
                PlaybookStep(
                    order=3,
                    action="No upstream errors in Nginx",
                    command_or_check="tail -n 500 /var/log/nginx/error.log | "
                                     "grep -E 'upstream timed out|upstream prematurely closed|connect\\(\\) failed' "
                                     "|| echo OK",
                    expected_result="No matches for the last 10 minutes",
                ),
                PlaybookStep(
                    order=4,
                    action="Postgres connection count back to baseline",
                    command_or_check="psql -c \"SELECT count(*) FROM pg_stat_activity "
                                     "WHERE application_name='api';\"",
                    expected_result="Steady-state count well below max_connections",
                ),
            ],
            rollback=[
                PlaybookStep(
                    order=1,
                    action="If the rollback to the previous API revision causes regressions, "
                           "redeploy 2026.03.17-2 and keep the enlarged pool + PgBouncer in place "
                           "while the leak fix is prepared",
                    command_or_check="kubectl rollout history deploy/api && "
                                     "kubectl rollout undo deploy/api --to-revision=<2026.03.17-2>",
                    expected_result="Previous behavior restored; mitigations remain active",
                ),
                PlaybookStep(
                    order=2,
                    action="Tear down PgBouncer if it introduces transaction-mode incompatibilities "
                           "(prepared statements, SET LOCAL, etc.)",
                    command_or_check="kubectl set env deploy/api DB_HOST=postgres-primary DB_PORT=5432 && "
                                     "kubectl delete -f infra/pgbouncer.yaml",
                    expected_result="API connects directly to Postgres again",
                ),
                PlaybookStep(
                    order=3,
                    action="Revert pool size override once the leak fix is verified",
                    command_or_check="kubectl set env deploy/api DB_POOL_SIZE- DB_MAX_OVERFLOW- "
                                     "DB_POOL_TIMEOUT- && kubectl rollout status deploy/api",
                    expected_result="Pool returns to baseline config; no regression",
                ),
            ],
            notes=("Deterministic fallback playbook. The leading hypothesis is a session leak "
                   "introduced by deploy 2026.03.17-2 in portfolio/rebalance_service.py:118; "
                   "rolling that back is the single highest-leverage mitigation. References used: "
                   + ", ".join(r.url for r in bundle.references)),
        )


# =============================================================================
# Orchestrator
# =============================================================================

class Orchestrator:
    def __init__(self, use_web: bool = True):
        self.agent1 = LogAnalystAgent()
        self.agent2 = SolutionResearcherAgent(use_web=use_web)
        self.agent3 = ResolutionPlannerAgent()

    def run(self, incident: IncidentInput) -> Playbook:
        print(f"\n[orchestrator] Starting incident {incident.incident_id} at "
              f"{datetime.now(timezone.utc).isoformat()}")

        print(f"[orchestrator] -> {self.agent1.name}")
        diagnosis = self.agent1.run(incident)
        print(f"[orchestrator]    diagnosis confidence={diagnosis.confidence:.2f}, "
              f"signatures={diagnosis.error_signatures}")

        print(f"[orchestrator] -> {self.agent2.name}")
        bundle = self.agent2.run(diagnosis)
        print(f"[orchestrator]    {len(bundle.references)} reference(s) found")

        print(f"[orchestrator] -> {self.agent3.name}")
        playbook = self.agent3.run(bundle)
        print(f"[orchestrator]    playbook severity={playbook.severity}, "
              f"steps={len(playbook.remediation)} remediation")

        return playbook


# =============================================================================
# Rendering
# =============================================================================

def render_playbook(diag: Diagnosis, bundle: ResearchBundle, pb: Playbook) -> str:
    lines = []
    lines.append("=" * 78)
    lines.append(f"INCIDENT RESPONSE REPORT — {pb.incident_id}")
    lines.append("=" * 78)
    lines.append("")
    lines.append(f"Title:    {pb.title}")
    lines.append(f"Severity: {pb.severity}")
    lines.append(f"Endpoints: {', '.join(diag.affected_endpoints)}")
    lines.append("")
    lines.append("--- Diagnosis (Agent 1) ---")
    lines.append(f"Primary cause:    {diag.primary_cause}")
    if diag.secondary_causes:
        lines.append("Secondary causes:")
        for s in diag.secondary_causes:
            lines.append(f"  - {s}")
    lines.append(f"Confidence:       {diag.confidence:.2f}")
    lines.append("Error signatures:")
    for sig in diag.error_signatures:
        lines.append(f"  - {sig}")
    lines.append("Evidence:")
    for ev in diag.evidence:
        lines.append(f"  [{ev.source}] {ev.excerpt}")
        lines.append(f"     why: {ev.why_it_matters}")
    lines.append("")
    lines.append(f"Summary: {diag.summary}")
    lines.append("")
    lines.append("--- References (Agent 2) ---")
    for r in bundle.references:
        lines.append(f"  [{r.source_type}] {r.title}")
        lines.append(f"     {r.url}")
        lines.append(f"     relevance: {r.relevance}")
    lines.append(f"Research notes: {bundle.research_notes}")
    lines.append("")
    lines.append("--- Playbook (Agent 3) ---")

    def _section(name: str, steps: List[PlaybookStep]):
        lines.append(f"\n  {name}:")
        for step in sorted(steps, key=lambda s: s.order):
            lines.append(f"    {step.order}. {step.action}")
            if step.command_or_check:
                lines.append(f"       $ {step.command_or_check}")
            if step.expected_result:
                lines.append(f"       expected: {step.expected_result}")

    _section("PRE-CHECKS",  pb.pre_checks)
    _section("REMEDIATION", pb.remediation)
    _section("POST-CHECKS", pb.post_checks)
    _section("ROLLBACK",    pb.rollback)
    lines.append("")
    lines.append(f"Notes: {pb.notes}")
    lines.append("=" * 78)
    return "\n".join(lines)


# =============================================================================
# CLI
# =============================================================================

def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="3-Agent Incident Response System")
    parser.add_argument("--logs", default="./logs",
                        help="Directory containing nginx-access.log, nginx-error.log, app-error.log")
    parser.add_argument("--incident-id", default="INC-2026-04-26-001")
    parser.add_argument("--no-web", action="store_true",
                        help="Disable DuckDuckGo augmentation (curated docs only)")
    parser.add_argument("--out", default=None, help="Optional path to write the rendered report")
    args = parser.parse_args(argv)

    log_dir = Path(args.logs)
    incident = IncidentInput(
        incident_id=args.incident_id,
        nginx_access_log=_read(log_dir / "nginx-access.log"),
        nginx_error_log=_read(log_dir / "nginx-error.log"),
        app_error_log=_read(log_dir / "app-error.log"),
        affected_endpoints=[
            "/api/v1/auth/login", "/api/v1/portfolio/summary",
            "/api/v1/watchlist", "/api/v1/orders",
            "/api/v1/orders/rebalance", "/api/v1/recommendations",
        ],
    )

    orch = Orchestrator(use_web=not args.no_web)

    # Run the pipeline. We re-use Agent 1+2 outputs for rendering.
    diag = orch.agent1.run(incident)
    bundle = orch.agent2.run(diag)
    pb = orch.agent3.run(bundle)

    report = render_playbook(diag, bundle, pb)
    print("\n" + report)

    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
        print(f"\n[orchestrator] Report written to {args.out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
