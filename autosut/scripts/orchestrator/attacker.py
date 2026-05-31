"""Attacker-side capability installer.

Capabilities are declared in catalog.py via the AttackerProfile.
This module turns each capability label into a concrete install recipe that
runs in a SEPARATE attacker container. The attacker container has network
reach to the SUT container.
"""

from __future__ import annotations

import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

from .models import AttackerProfile


CAPABILITY_INSTALL = {
    # python:3.11-slim already has python3 + pip; we just need curl + requests.
    "rpc_rce": "apt-get update -o Acquire::AllowInsecureRepositories=true 2>&1 | tail -2; "
               "apt-get install -y --allow-unauthenticated curl 2>&1 | tail -2; "
               "python3 -m pip install --no-cache-dir --root-user-action=ignore requests",
    "db_dump": "apt-get install -y --allow-unauthenticated default-mysql-client 2>&1 | tail -2",
    "pivot": "apt-get install -y --allow-unauthenticated openssh-client socat 2>&1 | tail -2",
    "cert_gen": "apt-get install -y --allow-unauthenticated openssl 2>&1 | tail -2",
    "web_rce": "apt-get install -y --allow-unauthenticated curl 2>&1 | tail -2",
}


@dataclass
class AttackerEnv:
    container_name: str
    run_dir: Path

    def run_shell(self, command: str, log_name: str | None = None,
                  timeout: int = 300):
        proc = subprocess.run(
            ["docker", "exec", self.container_name, "bash", "-c", command],
            capture_output=True, text=True, timeout=timeout,
        )
        if log_name:
            log_path = self.run_dir / log_name
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(
                f"$ {command}\nexit_code: {proc.returncode}\n"
                f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}\n",
                encoding="utf-8",
            )
        return proc


def bring_up_attacker(profile: AttackerProfile, run_dir: Path,
                      shared_network: str | None = None) -> AttackerEnv:
    container_name = f"autosut-att-{uuid.uuid4().hex[:8]}"
    base_image = "python:3.11-slim"
    args = [
        "docker", "run", "-d",
        "--name", container_name,
        "--rm",
        base_image,
        "sleep", "infinity",
    ]
    if shared_network:
        args[5:5] = ["--network", shared_network]
    subprocess.run(args, capture_output=True, text=True, check=True)

    env = AttackerEnv(container_name=container_name, run_dir=run_dir)
    log_path = run_dir / "attacker" / "install.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(f"# attacker bring-up\nimage: ubuntu:22.04\nname: {container_name}\n",
                        encoding="utf-8")

    env.run_shell("apt-get update", log_name="attacker/apt_update.log", timeout=300)
    for capability in profile.capabilities:
        recipe = CAPABILITY_INSTALL.get(capability)
        if recipe is None:
            continue
        env.run_shell(recipe, log_name=f"attacker/install_{capability}.log", timeout=300)
    return env


def teardown_attacker(env: AttackerEnv) -> bool:
    proc = subprocess.run(
        ["docker", "stop", env.container_name],
        capture_output=True, text=True, check=False, timeout=60,
    )
    log = env.run_dir / "attacker" / "teardown.log"
    log.write_text(
        f"docker stop {env.container_name}\nexit_code: {proc.returncode}\n"
        f"stdout: {proc.stdout}\nstderr: {proc.stderr}\n",
        encoding="utf-8",
    )
    return proc.returncode == 0
