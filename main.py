"""
main.py
=======
Orchestrator for the 3-agent incident-response pipeline.

Pipeline:
    IncidentInput
        -> Agent 1 (LogAnalystAgent, Gemini)         -> Diagnosis
        -> Agent 2 (SolutionResearcherAgent, no LLM) -> ResearchBundle
        -> Agent 3 (ResolutionPlannerAgent, Gemini)  -> Playbook
    -> render_playbook() -> stdout / --out file

Run:
    python log_generator.py            # produce ./logs/*.log
    export GEMINI_API_KEY=...          # or rely on the spec's default
    python main.py --logs ./logs --out ./report.txt
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from agents import (
    Diagnosis,
    IncidentInput,
    LogAnalystAgent,
    Playbook,
    PlaybookStep,
    ResearchBundle,
    ResolutionPlannerAgent,
    SolutionResearcherAgent,
)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class Orchestrator:
    def __init__(self, use_web: bool = True):
        self.agent1 = LogAnalystAgent()
        self.agent2 = SolutionResearcherAgent(use_web=use_web)
        self.agent3 = ResolutionPlannerAgent()

    def run(self, incident: IncidentInput) -> tuple[Diagnosis, ResearchBundle, Playbook]:
        print(f"[orchestrator] Starting incident {incident.incident_id} at "
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

        return diagnosis, bundle, playbook


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_playbook(diag: Diagnosis, bundle: ResearchBundle, pb: Playbook) -> str:
    lines: list[str] = []
    bar = "=" * 78
    lines += [bar, f"INCIDENT RESPONSE REPORT — {pb.incident_id}", bar, ""]
    lines += [
        f"Title:    {pb.title}",
        f"Severity: {pb.severity}",
        f"Endpoints: {', '.join(diag.affected_endpoints)}",
        "",
        "--- Diagnosis (Agent 1) ---",
        f"Primary cause:    {diag.primary_cause}",
    ]
    if diag.secondary_causes:
        lines.append("Secondary causes:")
        for s in diag.secondary_causes:
            lines.append(f"  - {s}")
    lines += [f"Confidence:       {diag.confidence:.2f}", "Error signatures:"]
    for sig in diag.error_signatures:
        lines.append(f"  - {sig}")
    lines.append("Evidence:")
    for ev in diag.evidence:
        lines.append(f"  [{ev.source}] {ev.excerpt}")
        lines.append(f"     why: {ev.why_it_matters}")
    lines += ["", f"Summary: {diag.summary}", "", "--- References (Agent 2) ---"]
    for r in bundle.references:
        lines.append(f"  [{r.source_type}] {r.title}")
        lines.append(f"     {r.url}")
        lines.append(f"     relevance: {r.relevance}")
    lines += [f"Research notes: {bundle.research_notes}", "", "--- Playbook (Agent 3) ---"]

    def _section(name: str, steps: List[PlaybookStep]) -> None:
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
    lines += ["", f"Notes: {pb.notes}", bar]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="3-Agent Incident Response System")
    parser.add_argument("--logs", default="./logs",
                        help="Directory with nginx-access.log, nginx-error.log, app-error.log")
    parser.add_argument("--incident-id", default="INC-2026-04-26-001")
    parser.add_argument("--no-web", action="store_true",
                        help="Disable DuckDuckGo augmentation in Agent 2")
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

    diag, bundle, pb = Orchestrator(use_web=not args.no_web).run(incident)
    report = render_playbook(diag, bundle, pb)
    print("\n" + report)
    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
        print(f"\n[orchestrator] Report written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
