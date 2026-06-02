#!/usr/bin/env python3
"""Generate the curated subdetermination proof artifact.

Writes release/subdetermination_proof.json with two proofs:
  - 0.cve_2021_41773 : executable witness (runs the real CVE when Docker is
    available, so `executable` reflects a live run).
  - 0.apt41_dust     : structural witness (large free region, material service
    substitution; never claimed to execute).

The reviewer dashboard and the release gate read this file; neither recomputes
the proof. The script is intentionally deterministic and self-contained.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from orchestrator import subdetermination  # noqa: E402

OUTPUT = PROJECT_ROOT / "release" / "subdetermination_proof.json"


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"],
                          capture_output=True).returncode == 0


def build_artifact(execute_cve: bool) -> dict:
    """Assemble the two-campaign proof artifact. Structural unless execute_cve."""
    cve = subdetermination.prove_subdetermination(
        "0.cve_2021_41773", n_variants=2, execute=execute_cve)
    apt41 = subdetermination.prove_subdetermination(
        "0.apt41_dust", n_variants=3, execute=False)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "proofs": {
            cve.campaign_id: cve.model_dump(mode="json"),
            apt41.campaign_id: apt41.model_dump(mode="json"),
        },
    }


def main() -> int:
    execute_cve = docker_available()
    if not execute_cve:
        print("[subdet] docker unavailable — cve proof will be structural only",
              file=sys.stderr)
    artifact = build_artifact(execute_cve=execute_cve)
    OUTPUT.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    cve = artifact["proofs"]["0.cve_2021_41773"]
    print(f"[subdet] wrote {OUTPUT}")
    print(f"[subdet] cve_2021_41773 executable={cve['executable']} "
          f"(invariant {cve['invariant_count']}, free {cve['free_count']}, "
          f"variants {len(cve['variants'])})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
