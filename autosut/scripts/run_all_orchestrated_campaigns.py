#!/usr/bin/env python3
"""Run every implemented orchestrated campaign sequentially.

Each campaign brings up its own SUT, injects CVEs (when declared), runs the
technique sequence, captures evidence, and tears the environment down before
the next one starts. The script prints a summary table at the end.

Usage:
    python3 scripts/run_all_orchestrated_campaigns.py
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))

from orchestrator import build_default, caldera_client
from orchestrator.catalog import implemented_campaigns


def ensure_caldera_ready(max_wait_seconds: int = 90) -> bool:
    """Bring the Caldera C2 up before the batch starts.

    A declared caldera_driven technique fails honestly when the C2 is
    unreachable, so the batch provisions the C2 rather than letting evidence
    degrade silently. Returns True once Caldera answers its health endpoint.
    """
    if caldera_client.probe().api_ok:
        return True

    print("[caldera] C2 unreachable; starting it before the batch ...")
    subprocess.run(
        ["docker", "start", "autosut-caldera"],
        check=False, capture_output=True, text=True,
    )
    deadline = time.monotonic() + max_wait_seconds
    while time.monotonic() < deadline:
        if caldera_client.probe().api_ok:
            print("[caldera] C2 ready.")
            return True
        time.sleep(5)

    print("[caldera] C2 still unreachable. Run ./scripts/up_lab.sh to provision "
          "it; caldera-driven techniques are otherwise recorded as failures.")
    return False


def main() -> int:
    ensure_caldera_ready()
    orch = build_default()
    rows: list[tuple[str, int, int, dict, str]] = []
    for cid in implemented_campaigns():
        print(f"\n=== Running {cid} ===")
        t0 = time.monotonic()
        try:
            result = orch.run_campaign(cid)
        except Exception as exc:
            rows.append((cid, 0, 0, {}, f"ERROR: {exc}"))
            continue
        elapsed = time.monotonic() - t0
        rows.append((
            cid,
            result.successful, result.total_techniques,
            result.fidelity_distribution,
            f"{elapsed:.1f}s",
        ))

    print("\n" + "=" * 88)
    print(f"{'campaign':<35} {'pass/total':>11}  {'fidelity':<28} elapsed")
    print("-" * 88)
    total_pass = total_all = 0
    fidelity_sum: dict[str, int] = {}
    for cid, ok, total, fidelity, elapsed in rows:
        total_pass += ok; total_all += total
        for k, v in fidelity.items():
            fidelity_sum[k] = fidelity_sum.get(k, 0) + v
        fid_str = ", ".join(f"{k}={v}" for k, v in sorted(fidelity.items()))
        print(f"{cid:<35} {ok:>3}/{total:<7d}  {fid_str:<28} {elapsed}")
    print("-" * 88)
    fid_total = ", ".join(f"{k}={v}" for k, v in sorted(fidelity_sum.items()))
    print(f"{'TOTAL':<35} {total_pass:>3}/{total_all:<7d}  {fid_total}")
    print("=" * 88)
    return 0 if total_pass == total_all else 2


if __name__ == "__main__":
    raise SystemExit(main())
