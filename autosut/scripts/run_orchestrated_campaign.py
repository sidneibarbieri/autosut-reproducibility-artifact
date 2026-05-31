#!/usr/bin/env python3
"""CLI entry point for the per-campaign orchestrator.

Usage:
    python3 scripts/run_orchestrated_campaign.py 0.shadowray

Runs one campaign tuple end to end: bring up SUT and attacker containers,
inject the declared CVEs, execute the techniques, capture per-technique
evidence, and tear everything down. Manifest is written under
release/evidence/<run_id>/.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Make the orchestrator package importable without installing it.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from orchestrator import build_default
from orchestrator.catalog import implemented_campaigns, known_campaigns


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "campaign",
        nargs="?",
        help=f"campaign id (one of: {', '.join(implemented_campaigns())})",
    )
    parser.add_argument("--list", action="store_true",
                        help="list all known campaigns and exit")
    args = parser.parse_args()

    if args.list:
        for cid in known_campaigns():
            marker = "✓" if cid in implemented_campaigns() else " "
            print(f" [{marker}] {cid}")
        return 0

    if not args.campaign:
        parser.print_help()
        return 1

    orch = build_default()
    result = orch.run_campaign(args.campaign)

    print(f"\n[orchestrator] run_id: {result.run_id}")
    print(f"[orchestrator] techniques: {result.successful}/{result.total_techniques} successful")
    print(f"[orchestrator] fidelity distribution: {result.fidelity_distribution}")
    print(f"[orchestrator] manifest: {result.manifest_path}")
    return 0 if result.successful == result.total_techniques else 2


if __name__ == "__main__":
    raise SystemExit(main())
