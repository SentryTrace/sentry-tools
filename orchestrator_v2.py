from __future__ import annotations

import argparse
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from crewai import Agent, Crew, LLM, Task
from crewai.tools.base_tool import Tool

# Logging
# ======================

logger = logging.getLogger("sentrytools.orchestrator")

def configure_logging(level: int = logging.INFO) -> None:
    """
    Configure structured logging for the orchestrator.
    """
    logging.basicConfig(
        level=level,
        format="[%(asctime)s] %(levelname)-7s %(name)s :: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

# Configuration
# =============================

MODULES_DIR: Path = Path(__file__).resolve().parent

DEFAULT_STEP_TIMEOUT: int = 120

ALLOWED_SCRIPTS: frozenset[str] = frozenset(
    {
        "recon_collector.py",
        "exposure_analyzer.py",
        "payload_safety_validator.py",
        "signal_correlator.py",
        "risk_prioritizer.py",
        "output_sanitizer.py",
        "report_generator.py",
    }
)

@dataclass(frozen=True)
class LLMConfig:
    """
    Local Ollama-served LLM configuration.
    """

    model: str = os.getenv(
        "ORCH_LLM_MODEL",
        "ollama/qwen2.5:14b-instruct"
    )

    base_url: str = os.getenv(
        "ORCH_LLM_BASE_URL",
        "http://localhost:11434"
    )

    provider: str = "ollama"

# CLI / URL validation
# =============================

class URLArgs(BaseModel):
    """
    Enforced schema for every tool invocation.
    """

    url: str = Field(
        ...,
        description="Authorized target URL locked by orchestrator."
    )

def parse_cli_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sentrytools-orchestrator",
        description=(
            "Authorized AI-assisted security workflow orchestrator "
            "for reconnaissance, exposure analysis, validation, "
            "prioritization and reporting."
        ),
    )

    parser.add_argument(
        "--url",
        required=True,
        help="Authorized target URL."
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_STEP_TIMEOUT,
        help=f"Default step timeout in seconds (default: {DEFAULT_STEP_TIMEOUT})."
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging."
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate pipeline configuration without executing modules."
    )

    parser.add_argument(
        "--safe-mode",
        action="store_true",
        help="Enable strict safe validation mode."
    )

    return parser.parse_args(argv)

def validate_target_url(raw: str) -> str:
    """
    Normalize and validate target URL.
    """
    if not raw or not raw.strip():
        raise ValueError("Target URL cannot be empty.")

    candidate = raw.strip()

    if "://" not in candidate:
        candidate = "https://" + candidate

    parsed = urlparse(candidate)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError(
            f"Unsupported scheme {parsed.scheme!r}; only http/https allowed."
        )

    if not parsed.netloc:
        raise ValueError("Target URL missing host.")

    return candidate

# Subprocess execution
# ===============================

def _build_cli_args(params: Mapping[str, Any]) -> list[str]:
    """
    Convert kwargs into CLI arguments.
    """
    cli: list[str] = []

    for key, value in params.items():

        if value is None or value is False:
            continue

        flag = f"--{key.replace('_', '-')}"

        if value is True:
            cli.append(flag)
        else:
            cli.extend([flag, str(value)])

    return cli

def run_module(
    script_name: str,
    *,
    target_url: str,
    extra: Mapping[str, Any] | None = None,
    timeout: int = DEFAULT_STEP_TIMEOUT,
) -> str:
    """
    Execute an allowlisted module safely.
    """

    if script_name not in ALLOWED_SCRIPTS:
        raise PermissionError(
            f"{script_name!r} is not allowlisted."
        )

    script_path = MODULES_DIR / script_name

    if not script_path.is_file():
        return f"[SKIP] Missing module: {script_name}"

    python_exe = (
        sys.executable
        or shutil.which("python3")
        or "python3"
    )

    params: dict[str, Any] = {
        "url": target_url
    }

    if extra:
        params.update(extra)

    params["url"] = target_url

    cmd = [
        python_exe,
        str(script_path),
        *_build_cli_args(params)
    ]

    logger.debug("Executing: %s", " ".join(cmd))

    started = datetime.now()

    try:

        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
            shell=False,
        )

    except subprocess.TimeoutExpired:

        logger.error(
            "Timeout exceeded for %s",
            script_name
        )

        return (
            f"[TIMEOUT] {script_name} exceeded "
            f"{timeout}s and was terminated."
        )

    except subprocess.CalledProcessError as exc:

        logger.error(
            "Module %s failed with rc=%s",
            script_name,
            exc.returncode
        )

        return (
            f"[ERROR] {script_name} (rc={exc.returncode})\n"
            f"{exc.stdout}\n{exc.stderr}"
        )

    except FileNotFoundError:

        logger.error("Python interpreter unavailable.")

        return "[ERROR] Python interpreter unavailable."

    elapsed = (datetime.now() - started).total_seconds()

    logger.info(
        "Module %s completed in %.2fs",
        script_name,
        elapsed
    )

    return completed.stdout


# Workflow model
# ==============================

@dataclass(frozen=True)
class WorkflowStep:

    key: str
    script: str
    role: str
    goal: str
    backstory: str
    description: str
    expected_output: str
    timeout: int = DEFAULT_STEP_TIMEOUT

WORKFLOW: tuple[WorkflowStep, ...] = (

    WorkflowStep(
        key="recon",
        script="recon_collector.py",
        role="Reconnaissance Collector",
        goal="Map the public attack surface of the authorized target.",
        backstory=(
            "Passive reconnaissance and OSINT specialist operating "
            "strictly within authorized scope."
        ),
        description="Passive reconnaissance and surface inventory.",
        expected_output="Structured reconnaissance dataset.",
    ),

    WorkflowStep(
        key="exposure",
        script="exposure_analyzer.py",
        role="Exposure Analyst",
        goal="Identify exposed assets and likely weaknesses.",
        backstory=(
            "Application security analyst correlating recon signals "
            "with known exposure patterns."
        ),
        description="Exposure analysis and candidate weakness mapping.",
        expected_output="List of candidate exposure points.",
    ),

    WorkflowStep(
        key="validation",
        script="payload_safety_validator.py",
        role="Controlled Validation Engineer",
        goal=(
            "Safely validate candidate exposures using "
            "low-impact requests."
        ),
        backstory=(
            "Focuses on minimally-invasive validation workflows "
            "with strict safety boundaries."
        ),
        description="Controlled validation of candidate findings.",
        expected_output="Validated findings with false positives removed.",
    ),

    WorkflowStep(
        key="correlation",
        script="signal_correlator.py",
        role="Signal Correlator",
        goal="Cluster and de-duplicate validated findings.",
        backstory=(
            "Aggregates findings from multiple signals "
            "to improve clarity and prioritization."
        ),
        description="Cross-source signal correlation.",
        expected_output="Consolidated findings dataset.",
    ),

    WorkflowStep(
        key="prioritization",
        script="risk_prioritizer.py",
        role="Risk Prioritizer",
        goal="Rank findings by likely impact and exploitability.",
        backstory=(
            "Applies severity and exploitability reasoning "
            "to support remediation prioritization."
        ),
        description="Risk-based prioritization.",
        expected_output="Prioritized findings with rationale.",
    ),

    WorkflowStep(
        key="sanitization",
        script="output_sanitizer.py",
        role="Output Sanitizer",
        goal="Redact secrets and sensitive information.",
        backstory=(
            "Ensures outputs remain share-safe and compliant."
        ),
        description="Sensitive data sanitization.",
        expected_output="Sanitized output artifacts.",
    ),

    WorkflowStep(
        key="report",
        script="report_generator.py",
        role="Report Generator",
        goal="Generate a clear remediation-focused report.",
        backstory=(
            "Produces actionable security reports "
            "with evidence and remediation guidance."
        ),
        description="Final report generation.",
        expected_output="Consolidated remediation-focused report.",
        timeout=180,
    ),
)

# CrewAI builders
# =======================

def _make_tool(step: WorkflowStep, target_url: str) -> Tool:

    def _runner(**kwargs: Any) -> str:

        kwargs.pop("url", None)

        return run_module(
            step.script,
            target_url=target_url,
            extra=kwargs,
            timeout=step.timeout,
        )

    return Tool(
        name=f"{step.key}_tool",
        func=_runner,
        description=f"{step.description} (authorized target only).",
        args_schema=URLArgs,
    )

def _make_agent(
    step: WorkflowStep,
    tool: Tool,
    llm: LLM
) -> Agent:

    backstory = (
        f"{step.backstory} "
        "Operate strictly within authorized scope. "
        "Do not modify the locked target URL."
    )

    return Agent(
        role=step.role,
        goal=step.goal,
        backstory=backstory,
        tools=[tool],
        llm=llm,
        verbose=True,
        allow_delegation=False,
    )

def build_pipeline(
    target_url: str,
    llm: LLM,
    steps: Iterable[WorkflowStep] = WORKFLOW,
) -> tuple[list[Agent], list[Task]]:

    agents: list[Agent] = []
    tasks: list[Task] = []

    for step in steps:

        tool = _make_tool(step, target_url)

        agent = _make_agent(step, tool, llm)

        agents.append(agent)

        task = Task(
            agent=agent,
            description=(
                f"{step.description}\n"
                f"Authorized target: {target_url}\n"
                "Use only the provided tool."
            ),
            expected_output=step.expected_output,
            context=tasks[-1:] if tasks else None,
        )

        tasks.append(task)

    return agents, tasks

def build_llm(
    config: LLMConfig | None = None
) -> LLM:

    cfg = config or LLMConfig()

    return LLM(
        model=cfg.model,
        base_url=cfg.base_url,
        provider=cfg.provider,
    )


# Reporting
# ======================

def format_results(
    tasks: list[Task],
    results: Any
) -> str:

    lines = [
        "",
        "=" * 72,
        "AUTHORIZED SECURITY WORKFLOW — FINAL REPORT",
        "=" * 72,
    ]

    task_outputs = (
        getattr(results, "tasks_output", None)
        or list(results or [])
    )

    for index, task in enumerate(tasks):

        role = (
            task.agent.role
            if task.agent
            else f"step-{index}"
        )

        try:
            output = task_outputs[index]
        except IndexError:
            output = "(no output)"

        lines.append(f"\n--- Step {index + 1}: {role} ---")
        lines.append(str(output).rstrip())

    lines.append("\n" + "=" * 72)

    return "\n".join(lines)

# Entry point
# ===================

def main(argv: list[str] | None = None) -> int:

    cli = parse_cli_args(argv)

    configure_logging(
        logging.DEBUG if cli.verbose else logging.INFO
    )

    try:
        target_url = validate_target_url(cli.url)

    except ValueError as exc:

        logger.error("Invalid URL: %s", exc)

        return 2

    logger.info(
        "Authorized target locked: %s",
        target_url
    )

    os.environ["ORCH_TARGET_URL"] = target_url

    if cli.safe_mode:
        os.environ["ORCH_SAFE_MODE"] = "1"

    llm = build_llm()

    agents, tasks = build_pipeline(
        target_url,
        llm
    )

    if cli.dry_run:

        logger.info(
            "Dry-run completed successfully."
        )

        print(
            f"[DRY-RUN] {len(tasks)} workflow steps configured successfully."
        )

        return 0

    crew = Crew(
        agents=agents,
        tasks=tasks,
        verbose=True,
    )

    logger.info(
        "Starting workflow with %d steps.",
        len(tasks)
    )

    try:

        results = crew.kickoff()

    except Exception:

        logger.exception(
            "Workflow execution failed."
        )

        return 1

    print(format_results(tasks, results))

    logger.info(
        "Workflow completed successfully."
    )

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
