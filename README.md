# SentryTools — AI-Assisted Security Workflow Automation

SentryTools is a Python-based security automation project designed to support authorized attack surface analysis, exposure validation, signal correlation, risk prioritization, and remediation-focused reporting.
The goal is not to generate large volumes of raw scan data, but to reduce noise, correlate signals, and help security teams move from reconnaissance output to actionable security insight.

---
## Purpose
Modern security testing produces large amounts of fragmented data.
SentryTools focuses on:
- reducing false positives and duplicate signals
- correlating outputs across multiple discovery and validation stages
- prioritizing findings based on exploitability and business impact
- supporting controlled, low-impact validation workflows
- producing clean, share-safe reporting artifacts
> Built for authorized security research, AppSec workflows, and offensive security automation.
---
## Core Capabilities
### Reconnaissance Collection
- public attack surface mapping
- subdomain and endpoint discovery
- HTTP probing and service fingerprinting
- structured JSON output for downstream analysis
### Exposure Analysis
- identification of exposed assets and weak security patterns
- response behavior analysis
- access-control and misconfiguration indicators
- candidate finding generation
### Controlled Validation
- low-impact validation of candidate exposures
- false-positive reduction
- safe request boundaries
- authorized-target enforcement
### Signal Correlation
- clustering and de-duplication of findings
- correlation across hosts, endpoints, services, and response patterns
- confidence scoring
- signal-over-volume prioritization
### Risk Prioritization
- exploitability-based ranking
- impact-oriented reasoning
- remediation priority guidance
- focus on realistic attack paths rather than isolated signals
### Output Sanitization
- redaction of sensitive information
- share-safe report preparation
- reduction of accidental data exposure
- compliance-friendly output handling
### Reporting
- structured technical summaries
- evidence-focused finding descriptions
- remediation guidance
- final consolidated workflow report
---
## AI-Assisted Orchestration
SentryTools includes an experimental CrewAI-based orchestrator:
```text
 Recon Collection
      ↓
 Exposure Analysis
      ↓
 Controlled Validation
      ↓
 Signal Correlation
      ↓
 Risk Prioritization
      ↓
 Output Sanitization
      ↓
 Report Generation
```

The orchestrator is designed to coordinate modular security workflow components while keeping the target URL locked at the orchestration layer.

Key design choices:

* allowlisted module execution
* locked authorized target URL
* local LLM support via Ollama
* subprocess isolation
* timeout handling
* structured logging
* dry-run mode
* safe-mode support

⸻

Main Components

sentry_recon.py

A lightweight reconnaissance pipeline for:

* subdomain candidate generation
* DNS resolution
* HTTP probing
* wildcard DNS filtering
* status-code filtering
* response-size baselining
* JSON reporting

orchestrator_V2.py

An AI-assisted workflow orchestrator designed around authorized security testing.

Current planned modules:

recon_collector.py
exposure_analyzer.py
payload_safety_validator.py
signal_correlator.py
risk_prioritizer.py
output_sanitizer.py
report_generator.py

The orchestrator uses an allowlist to prevent arbitrary module execution and keeps the target URL locked across all workflow steps.

⸻

Design Principles

* authorized testing only
* signal over volume
* low-impact validation
* local-first AI analysis
* reproducible workflows
* structured reporting
* sensitive-output sanitization
* remediation-oriented results

⸻

Project Status

Active development.

This repository currently represents an evolving security automation prototype focused on:

* improving attack surface workflow automation
* reducing reconnaissance noise
* building safer validation pipelines
* integrating local LLM-assisted triage
* producing clearer security reports

⸻

Use Cases

* authorized external attack surface assessment
* AppSec research workflows
* bug bounty reconnaissance within program scope
* pre-engagement pentest reconnaissance
* exposure discovery and prioritization
* security report generation

⸻

Responsible Use

This project is intended only for:

* authorized security testing
* educational research
* internal security validation
* defensive exposure analysis

Do not use this project against systems without explicit permission.

⸻

Related Research

Applied research and anonymized case studies are available in:

SentryTrace / sentrytrace-research

These case studies focus on attack surface exposure, authentication abuse patterns, publicly exposed assets, and remediation-oriented security analysis.

⸻

Contact

contact@sentrytrace.com

⸻

Final Note

Tools do not replace security reasoning.

The value of automation is not just speed — it is reducing noise, preserving context, and helping researchers understand how systems fail.
