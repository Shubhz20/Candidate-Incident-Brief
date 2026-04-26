# Candidate Incident Brief

## Scenario

You are building a real 3-agent incident-response system for a Linux-hosted production API.

In the last 20 minutes:
- API latency increased sharply
- users started reporting failures on login and portfolio endpoints
- the load balancer health check is still intermittently passing

You have been given:
- `nginx-access.log`
- `nginx-error.log`
- `app-error.log`

## Objective

Build a working AI-agent workflow that can process the supplied logs and produce an incident-response recommendation.

This is a software implementation task, not a documentation-only exercise.

Your solution should run end-to-end and show how 3 agents collaborate on the same incident:

1. Log Analysis Agent
2. Solution Research Agent
3. Resolution Planner Agent

## What You Need To Build

Implement a runnable system that:

- ingests the provided log files
- executes the 3-agent workflow
- passes structured outputs from one agent to the next
- produces a final incident report and recommended action plan
- can be run locally by the reviewer using your instructions

You may use any stack you prefer, but your submission must be executable and reasonably easy to review.

## LLM Configuration

If you use Gemini for Agent 1 and/or Agent 3, read the API key from an environment variable.

Preferred model:

```text
gemini-2.5-flash
```

Use the following placeholder in your local configuration:

```env
GEMINI_API_KEY= AIzaSyDSwQefcHaNlPVACw5Vp710WqIivbayGpw
```

Keep the key outside source code. Do not hardcode secrets in the repository.

## Agent Responsibilities

### Agent 1: Log Analysis Agent

Responsibilities:
- read and analyze the provided logs
- identify the most likely issue or bug
- extract the strongest log evidence supporting that conclusion
- highlight uncertainty, missing evidence, or alternate hypotheses

Minimum expected output:
- suspected root cause
- supporting log snippets or patterns
- confidence level
- structured handoff for Agent 2

Notes:
- Agent 1 may use an LLM to analyze the logs, identify the issue, and diagnose the likely root cause
- if you use an LLM, make the prompts and orchestration visible in the codebase

### Agent 2: Solution Research Agent

Responsibilities:
- take Agent 1's diagnosis as input
- research possible fixes or remediation options by web scraping or direct retrieval from technical sources
- compare multiple possible solutions
- flag risky fixes, weak sources, and actions that should not be attempted first in production

Minimum expected output:
- list of possible solutions
- pros and cons of each solution
- source-backed reasoning
- structured recommendation handoff for Agent 3

Notes:
- Agent 2 must use web scraping or direct source retrieval for solution research
- do not use an LLM as the primary mechanism for solution discovery in Agent 2
- prefer reliable technical sources such as official documentation, vendor docs, incident writeups, and high-quality engineering references
- include the URLs or source identifiers used during research
- if live web access is unavailable in your environment, clearly explain your fallback approach and what is missing because of that limitation

### Agent 3: Resolution Planner Agent

Responsibilities:
- review Agent 1 findings and Agent 2 solution options
- select the safest and most practical solution
- convert that solution into clear step-by-step operator instructions
- include validation steps before, during, and after the fix

Minimum expected output:
- best recommended solution
- ordered remediation steps
- pre-checks
- post-fix validation checks
- rollback or safety notes if the fix fails

Notes:
- Agent 3 may use an LLM to evaluate Agent 1 and Agent 2 outputs, select the best solution, and convert it into step-by-step remediation instructions
- if you use an LLM, make the prompts and orchestration visible in the codebase

## Required Deliverables

Your submission must include:

1. Source code for the working system
2. A short `README` with setup and run instructions
3. A sample execution result for the provided logs
4. A brief explanation of:
   - agent boundaries
   - handoff format between agents
   - why your implementation choices are production-reasonable

## What We Will Evaluate

We will evaluate:

- whether the system actually runs
- quality of agent separation and handoff design
- quality of log reasoning and evidence extraction
- practicality and safety of remediation advice
- source quality for research-backed recommendations
- clarity of setup and reviewer usability

## Final Submission Format

Please submit a runnable project folder or repository plus a short summary document.

The summary should include:

1. how to run the system
2. what the system concluded for this incident
3. any limitations, assumptions, or missing production safeguards
