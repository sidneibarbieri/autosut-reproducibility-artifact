"""Dispatch a single Caldera ability against a per-campaign sandcat agent.

This module is the integration point between the orchestrator and the running
MITRE Caldera C2. For each technique whose campaign declares
``expected_mode: caldera_driven``, the executor calls
:func:`dispatch_via_caldera`, which:

1. Ensures a sandcat agent is registered for this SUT container (installing
   and starting it on first call).
2. Creates a one-off Caldera adversary containing just the matching ART
   ability.
3. Starts an operation with the atomic planner against the agent's group.
4. Waits for the operation to finish, fetches the per-link report, and
   captures stdout/stderr/exit_code under ``run_dir/caldera/``.

The returned :class:`CalderaLinkResult` is consumed by the executor to build
a :class:`TechniqueOutcome` with ``executed_mode=caldera_driven`` and the
operation/link/ability IDs threaded into the manifest for auditability.
"""

from __future__ import annotations

import platform as _platform
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import caldera_client


SANDCAT_PATH_IN_CONTAINER = "/usr/local/bin/sandcat"
SANDCAT_LOG_IN_CONTAINER = "/tmp/sandcat.log"
DEFAULT_GROUP = "red"

# One paw per (container, campaign run) keeps the agent inventory clean and
# means consecutive techniques on the same container share an agent.
_paw_by_container: dict[str, str] = {}


@dataclass
class CalderaLinkResult:
    """Outcome of dispatching one ability via Caldera."""

    ok: bool
    technique_id: str
    ability_id: str
    ability_name: str
    operation_id: Optional[str] = None
    link_id: Optional[str] = None
    status: Optional[int] = None  # Caldera status: 0 = success
    stdout: str = ""
    stderr: str = ""
    exit_code: Optional[str] = None
    paw: Optional[str] = None
    evidence_files: list[str] = field(default_factory=list)
    error: Optional[str] = None


def _host_arch_for_sandcat() -> str:
    machine = _platform.machine().lower()
    if machine in ("aarch64", "arm64"):
        return "arm64"
    return "amd64"


def _agent_paw(container: str) -> str:
    paw = _paw_by_container.get(container)
    if paw is None:
        paw = f"autosut{uuid.uuid4().hex[:8]}"
        _paw_by_container[container] = paw
    return paw


def _container_has_sandcat(container: str) -> bool:
    proc = subprocess.run(
        ["docker", "exec", container, "test", "-x", SANDCAT_PATH_IN_CONTAINER],
        capture_output=True, text=True, check=False,
    )
    return proc.returncode == 0


def _install_sandcat(container: str) -> bool:
    arch = _host_arch_for_sandcat()
    binary = caldera_client.download_sandcat(platform="linux", architecture=arch)
    if not binary:
        return False
    tmp = Path(f"/tmp/sandcat_{container}.bin")
    tmp.write_bytes(binary)
    cp = subprocess.run(
        ["docker", "cp", str(tmp), f"{container}:{SANDCAT_PATH_IN_CONTAINER}"],
        capture_output=True, text=True, check=False,
    )
    tmp.unlink(missing_ok=True)
    if cp.returncode != 0:
        return False
    chmod = subprocess.run(
        ["docker", "exec", container, "chmod", "+x", SANDCAT_PATH_IN_CONTAINER],
        capture_output=True, text=True, check=False,
    )
    return chmod.returncode == 0


def _start_sandcat(container: str, caldera_url: str, paw: str,
                   group: str = DEFAULT_GROUP) -> None:
    cmd = (
        f"nohup {SANDCAT_PATH_IN_CONTAINER} "
        f"-server {caldera_url} "
        f"-group {group} "
        f"-paw {paw} "
        f"-v >{SANDCAT_LOG_IN_CONTAINER} 2>&1 &"
    )
    subprocess.run(
        ["docker", "exec", "-d", container, "bash", "-c", cmd],
        capture_output=True, text=True, check=False,
    )


def ensure_agent(container: str, run_dir: Path,
                 group: str = DEFAULT_GROUP) -> Optional[dict]:
    """Idempotently bring a sandcat agent up inside ``container`` and wait
    until Caldera registers it. Returns the agent dict on success.

    Idempotency strategy: first ask Caldera whether the paw associated with
    this container is already registered. If yes, return that agent without
    touching the container. Only fall through to install+start+wait when no
    agent is present, which guarantees we never spawn duplicate sandcats.
    """
    paw = _agent_paw(container)

    # Already registered? Cheap REST query, no container exec needed.
    existing = caldera_client.wait_agent_registered(
        paw_substring=paw, group=group, max_seconds=2, poll_seconds=0.5,
    )
    if existing:
        return existing

    if not _container_has_sandcat(container):
        if not _install_sandcat(container):
            return None
    caldera_ip = caldera_client.container_ip()
    if not caldera_ip:
        return None
    caldera_url = f"http://{caldera_ip}:8888"
    _start_sandcat(container, caldera_url, paw, group=group)
    agent = caldera_client.wait_agent_registered(paw_substring=paw,
                                                  group=group,
                                                  max_seconds=45)
    # Persist a small breadcrumb so a reviewer reading run_dir/ can confirm
    # the C2 channel was real.
    crumb = run_dir / "caldera" / f"agent_{paw}.txt"
    crumb.parent.mkdir(parents=True, exist_ok=True)
    crumb.write_text(
        f"caldera_url={caldera_url}\npaw={paw}\nregistered={bool(agent)}\n"
        f"agent={agent}\n",
        encoding="utf-8",
    )
    return agent


def dispatch_via_caldera(container: str, technique_id: str,
                         run_dir: Path,
                         preferred_platform: str = "linux",
                         operation_timeout_s: int = 90
                         ) -> CalderaLinkResult:
    """Run a single ART ability for ``technique_id`` against the agent in
    ``container``. Returns a CalderaLinkResult; if anything along the chain
    fails, ``ok=False`` and ``error`` carries the failure point."""
    ability = caldera_client.best_ability_for(technique_id, preferred_platform)
    if not ability:
        return CalderaLinkResult(
            ok=False, technique_id=technique_id, ability_id="", ability_name="",
            error=f"no Caldera ability for {technique_id}",
        )
    ability_id = ability.get("ability_id") or ""
    ability_name = ability.get("name") or ""

    agent = ensure_agent(container, run_dir)
    if not agent:
        return CalderaLinkResult(
            ok=False, technique_id=technique_id,
            ability_id=ability_id, ability_name=ability_name,
            error="sandcat agent did not register with Caldera",
        )

    adv_id = caldera_client.create_adversary(
        name=f"autosut-{technique_id}-{uuid.uuid4().hex[:6]}",
        ability_ids=[ability_id],
        description=f"AutoSUT one-off adversary for {technique_id}",
    )
    if not adv_id:
        return CalderaLinkResult(
            ok=False, technique_id=technique_id,
            ability_id=ability_id, ability_name=ability_name,
            error="create_adversary failed",
        )

    op_name = f"autosut-{technique_id}-{int(time.time())}"
    op_id = caldera_client.start_operation(name=op_name, adversary_id=adv_id)
    if not op_id:
        return CalderaLinkResult(
            ok=False, technique_id=technique_id,
            ability_id=ability_id, ability_name=ability_name,
            error="start_operation failed",
        )

    op = caldera_client.wait_operation_done(op_id, max_seconds=operation_timeout_s)
    report = caldera_client.get_operation_report(op_id) or {}

    paw = _paw_by_container.get(container, "")
    # Find the link that matches our ability + agent.
    link: Optional[dict] = None
    for paw_in_report, info in report.get("steps", {}).items():
        for cand in info.get("steps", []):
            if cand.get("ability_id") == ability_id:
                link = cand
                if paw_in_report == paw:
                    break
        if link:
            break

    # Persist the full report for reviewer auditability.
    evidence: list[str] = []
    report_path = run_dir / "caldera" / f"{technique_id}_{op_id}_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    import json as _json
    report_path.write_text(_json.dumps(report, indent=2), encoding="utf-8")
    evidence.append(str(report_path.relative_to(run_dir)))

    if link is None:
        # Operation finished but no link for our ability — usually means the
        # planner skipped it (platform mismatch, unsatisfied facts, etc.).
        skipped = report.get("skipped_abilities", [])
        return CalderaLinkResult(
            ok=False, technique_id=technique_id,
            ability_id=ability_id, ability_name=ability_name,
            operation_id=op_id, paw=paw,
            evidence_files=evidence,
            error=f"no link in report; skipped={skipped[:1]} state={op.get('state') if op else 'unknown'}",
        )

    output = link.get("output", {}) or {}
    if isinstance(output, str):
        stdout, stderr, exit_code = output, "", None
    else:
        stdout = output.get("stdout") or ""
        stderr = output.get("stderr") or ""
        exit_code = output.get("exit_code")

    # Persist the per-link stdout/stderr for grep-friendly inspection.
    log_path = run_dir / "caldera" / f"{technique_id}_{link.get('link_id')}.log"
    log_path.write_text(
        f"# Caldera link\n"
        f"operation_id: {op_id}\nlink_id: {link.get('link_id')}\n"
        f"ability_id: {ability_id}\nability_name: {ability_name}\n"
        f"command: {link.get('plaintext_command')}\n"
        f"status: {link.get('status')}\nexit_code: {exit_code}\n"
        f"--- stdout ---\n{stdout}\n"
        f"--- stderr ---\n{stderr}\n",
        encoding="utf-8",
    )
    evidence.append(str(log_path.relative_to(run_dir)))

    return CalderaLinkResult(
        ok=(link.get("status") == 0),
        technique_id=technique_id,
        ability_id=ability_id, ability_name=ability_name,
        operation_id=op_id, link_id=link.get("link_id"),
        status=link.get("status"),
        stdout=stdout, stderr=stderr, exit_code=str(exit_code) if exit_code is not None else None,
        paw=paw, evidence_files=evidence,
    )
