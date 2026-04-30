# SentryTools — Offensive Security Automation

SentryTools is a collection of offensive security tooling designed to automate attack surface mapping, reconnaissance, and vulnerability triage.

The goal is not just to scan targets — but to reduce noise, correlate findings, and prioritize real exploitation paths.

---

## ⚔️ Purpose

Modern recon produces massive amounts of data.

SentryTools focuses on:

- Eliminating noise (false positives, duplicates, wildcards)
- Correlating multi-tool outputs
- Identifying high-signal attack vectors
- Assisting real-world exploitation workflows

> Built for offensive security, not compliance scanning.

---

## 🧠 Core Capabilities

### 🔍 Recon Orchestration
- Multi-tool chaining (subfinder, httpx, nuclei, nmap, ffuf, etc.)
- Modular execution pipeline (run blocks independently)
- Automated target expansion (subdomains, endpoints, services)

### 🧹 Noise Reduction
- Wildcard DNS detection
- Soft-404 baseline filtering
- Response deduplication
- Fingerprint-based clustering

### 🔗 Cross-Tool Correlation
- Subdomain + service + vulnerability linking
- Ownership validation (e.g. cloud buckets)
- Exposure verification across multiple signals

### 🎯 Vulnerability Triage
- Prioritization based on exploitability
- Signal scoring (confidence vs noise)
- Focus on real attack paths (not isolated findings)

### 🤖 LLM-Assisted Analysis (Local)
- Offline analysis via Ollama
- JSON → structured attack insights
- No data leakage to external APIs
- Converts recon output into actionable intelligence

---

## ⚙️ Architecture

SentryTools follows a modular pipeline:

 \[Recon] → \[Filtering] → \[Correlation] → \[Triage] → \[Output] 

Each stage can be executed independently for flexibility and debugging.

---

## 🔐 Design Principles

- Offensive-first mindset
- Automation where it matters
- Signal over volume
- Stealth-aware execution (rate limiting, jitter)
- Local-first (no dependency on external AI APIs)

---

## 📁 Project Structure

 /tools /recon /filtering /correlation /triage /utils 

(structure may evolve as tooling expands)

---

## 🚧 Status

Active development.

This repository represents ongoing work to:

- Improve recon automation pipelines
- Enhance signal filtering techniques
- Integrate AI-assisted vulnerability triage
- Build scalable offensive workflows

---

## 🎯 Use Cases

- Bug bounty reconnaissance
- External attack surface mapping
- Pre-engagement recon for pentests
- Exposure discovery at scale
- Rapid triage of large scan outputs

---

## ⚠️ Disclaimer

This project is intended for:

- Authorized security testing
- Research and educational purposes

Do not use against systems without permission.

---

## 📬 Contact

contact@sentrytrace.com

---

## ⚡ Final Note

Tools don’t find vulnerabilities.

Understanding how systems fail does.
