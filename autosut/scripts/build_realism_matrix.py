"""Build the frozen-vs-AutoSUT realism matrix.

Reads, per canonical campaign:

- The frozen SUT profile YAML under
  the frozen STICKS ``data/sut_profiles/`` directory
  (the published artifact's declaration of what the SUT should be).
- The AutoSUT golden run under ``release/evidence/<run_id>/``
  (manifest.json + composition_target.json + caldera/*.log).

Emits two artefacts side-by-side:

- ``release/REALISM_MATRIX.md`` for the study-facing reviewer.
- ``release/realism_matrix.json`` for downstream tooling.

No prose. Each row is evidence the reviewer can grep against the cited
files. Columns: campaign, frozen hosts/services/credentials/files,
AutoSUT hosts/services/credentials/files, AutoSUT applications,
AutoSUT cves, technique pass rate, fidelity distribution, evidence path.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GOLDEN_RUNS_PATH = PROJECT_ROOT / "release" / "golden_runs.json"
FROZEN_PROFILES_ROOT = Path(
    os.environ.get("FROZEN_STICKS_SUT_PROFILES", ""))
OUTPUT_MD = PROJECT_ROOT / "release" / "REALISM_MATRIX.md"
OUTPUT_JSON = PROJECT_ROOT / "release" / "realism_matrix.json"


@dataclass
class FrozenView:
    """What the frozen sticks/ profile declares (read-only)."""

    found: bool
    hosts: list[str]
    services: list[str]
    credentials: list[str]
    files: list[str]
    deliberate_weaknesses: list[str]
    fidelity_expectations: dict[str, str]


@dataclass
class AutoSutView:
    """What the AutoSUT golden run actually applied."""

    golden_run_id: str
    evidence_path: str
    techniques_total: int
    techniques_success: int
    hosts: list[str]
    composition_credentials: list[str]
    composition_artifacts: list[str]
    composition_applications: list[str]
    composition_exposures: list[str]
    composition_cves: list[str]
    caldera_operations: int
    fidelity_distribution: dict[str, int]


def _read_frozen_view(campaign_id: str) -> FrozenView:
    profile_path = FROZEN_PROFILES_ROOT / f"{campaign_id}.yml"
    if not profile_path.exists():
        return FrozenView(False, [], [], [], [], [], {})
    data = yaml.safe_load(profile_path.read_text(encoding="utf-8")) or {}
    hosts = data.get("requirements", {}).get("required_vms", [])
    sut_config = data.get("sut_configuration", {}) or {}
    services: list[str] = []
    credentials: list[str] = []
    files: list[str] = []
    deliberate_weaknesses: list[str] = []
    for _host_name, host_config in sut_config.items():
        for service in host_config.get("services", []) or []:
            services.append(f"{service.get('name', '?')}@{service.get('version', '?')}")
        for user in host_config.get("users", []) or []:
            credentials.append(f"{user.get('username', '?')}:{user.get('password', '?')}")
        for file_entry in host_config.get("files", []) or []:
            files.append(file_entry.get("path", "?"))
        for weakness in host_config.get("deliberate_weaknesses", []) or []:
            deliberate_weaknesses.append(weakness.get("type", "?"))
    fidelity_expectations = data.get("fidelity_expectations", {}) or {}
    return FrozenView(
        found=True,
        hosts=list(hosts),
        services=services,
        credentials=credentials,
        files=files,
        deliberate_weaknesses=deliberate_weaknesses,
        fidelity_expectations=dict(fidelity_expectations),
    )


def _read_autosut_view(entry: dict[str, Any]) -> AutoSutView:
    run_dir = Path(entry["evidence_path"])
    if not run_dir.is_absolute():
        run_dir = PROJECT_ROOT / entry["evidence_path"]
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    techniques = manifest.get("techniques", [])
    successful = sum(1 for tech in techniques if tech.get("status") == "success")

    composition_credentials: list[str] = []
    composition_artifacts: list[str] = []
    composition_applications: list[str] = []
    composition_exposures: list[str] = []
    composition_cves: list[str] = []
    hosts_seen: list[str] = []
    sut_dir = run_dir / "sut"
    if sut_dir.exists():
        for composition_path in sorted(sut_dir.glob("composition_*.json")):
            host_label = composition_path.stem.replace("composition_", "")
            hosts_seen.append(host_label)
            composition = json.loads(composition_path.read_text(encoding="utf-8"))
            for credential in composition.get("credentials", []):
                composition_credentials.append(
                    f"{host_label}:{credential['user']}:{credential['secret']}")
            for artifact in composition.get("artifacts", []):
                composition_artifacts.append(f"{host_label}:{artifact['path']}")
            for application in composition.get("applications", []):
                composition_applications.append(
                    f"{host_label}:{application['name']}@{application['version']}")
                for cve_id in application.get("cve_pins", []):
                    composition_cves.append(cve_id)
            for exposure in composition.get("exposures", []):
                composition_exposures.append(
                    f"{host_label}:{exposure['port']}/{exposure['protocol']}")

    caldera_dir = run_dir / "caldera"
    caldera_operations = len(list(caldera_dir.glob("*_report.json"))) \
        if caldera_dir.exists() else 0

    fidelity_distribution: dict[str, int] = {}
    for tech in techniques:
        fidelity = tech.get("executed_fidelity", "?")
        fidelity_distribution[fidelity] = fidelity_distribution.get(fidelity, 0) + 1

    return AutoSutView(
        golden_run_id=entry["golden_run_id"],
        evidence_path=str(run_dir.relative_to(PROJECT_ROOT)),
        techniques_total=len(techniques),
        techniques_success=successful,
        hosts=hosts_seen,
        composition_credentials=composition_credentials,
        composition_artifacts=composition_artifacts,
        composition_applications=composition_applications,
        composition_exposures=composition_exposures,
        composition_cves=composition_cves,
        caldera_operations=caldera_operations,
        fidelity_distribution=fidelity_distribution,
    )


def _format_list(items: list[str], max_display: int = 3) -> str:
    if not items:
        return "—"
    if len(items) <= max_display:
        return ", ".join(items)
    return f"{', '.join(items[:max_display])} (+{len(items) - max_display} more)"


def _row_for_campaign(campaign_id: str, autosut_view: AutoSutView,
                       frozen_view: FrozenView) -> dict[str, Any]:
    return {
        "campaign_id": campaign_id,
        "frozen": {
            "profile_found": frozen_view.found,
            "hosts": frozen_view.hosts,
            "services": frozen_view.services,
            "credentials_declared": frozen_view.credentials,
            "files_declared": frozen_view.files,
            "deliberate_weaknesses": frozen_view.deliberate_weaknesses,
        },
        "autosut": {
            "golden_run_id": autosut_view.golden_run_id,
            "evidence_path": autosut_view.evidence_path,
            "hosts_applied": autosut_view.hosts,
            "credentials_applied": autosut_view.composition_credentials,
            "files_applied": autosut_view.composition_artifacts,
            "applications_applied": autosut_view.composition_applications,
            "exposures_declared": autosut_view.composition_exposures,
            "cve_pins": autosut_view.composition_cves,
            "techniques_total": autosut_view.techniques_total,
            "techniques_success": autosut_view.techniques_success,
            "caldera_operations": autosut_view.caldera_operations,
            "fidelity_distribution": autosut_view.fidelity_distribution,
        },
    }


def _render_markdown(rows: list[dict[str, Any]]) -> str:
    golden_payload = json.loads(GOLDEN_RUNS_PATH.read_text(encoding="utf-8"))
    tier_by_campaign = {
        entry["campaign_id"]: entry["tier"]
        for entry in golden_payload.get("campaigns", [])
    }
    scope_by_campaign = {
        entry["campaign_id"]: entry.get("cti_scope_type", "?")
        for entry in golden_payload.get("campaigns", [])
    }
    lines = [
        "# Frozen vs AutoSUT — Realism Matrix",
        "",
        "Objective per-campaign comparison. Every cell links to an artefact "
        "the reviewer can grep against:",
        "",
        "- **Frozen columns**: declared in `sticks/data/sut_profiles/*.yml`.",
        "- **AutoSUT columns**: actually applied; sourced from the golden run "
        "under `release/evidence/<run>/`.",
        "- **Tier**: `tier_1_full_real` means every technique ran via "
        "real_controlled / caldera_driven / atomic_red_team. "
        "`tier_2_declared_limitations` means the run was 100% successful but "
        "contains naive_simulated markers for techniques the Linux substrate "
        "cannot execute (Windows-only TTPs etc.) — an honest limitation, not "
        "a failure.",
        "- **Scope**: `campaign` = specific historical event with "
        "CVE-anchored attribution; `intrusion_set` = behavioral aggregate "
        "of a documented adversary group (less specific by design).",
        "",
        "Empty cells (`—`) mean the dimension was not declared or not applied. "
        "We never paper over a gap.",
        "",
        "## Claim scope (paper-defensible)",
        "",
        "> Campaign emulation instantiates a declared subset of "
        "ATT&CK-linked behaviors in a SUT whose software, credentials, "
        "services, topology, and vulnerability state are explicitly "
        "composed and logged. The goal is bounded, auditable replay of "
        "the environment-conditioned behaviors supported by the CTI scope "
        "— not historical reconstruction of the original intrusion.",
        "",
        "| Campaign | Scope | Tier | Frozen hosts | Frozen services | Frozen credentials | AutoSUT hosts | AutoSUT applications (CVEs) | AutoSUT credentials | AutoSUT exposures | Techniques | Caldera ops | Fidelity dist | Evidence |",
        "|---|---|---|---|---|---|---|---|---|---|---:|---:|---|---|",
    ]
    for row in rows:
        frozen = row["frozen"]
        autosut = row["autosut"]
        applications = autosut["applications_applied"]
        cves = autosut["cve_pins"]
        if applications and cves:
            applications_display = (
                ", ".join(applications) +
                " [pins: " + ", ".join(cves) + "]"
            )
        else:
            applications_display = _format_list(applications)
        ratio = (f"{autosut['techniques_success']}/{autosut['techniques_total']}"
                 if autosut["techniques_total"] else "—")
        fidelity_display = (
            ", ".join(f"{key}:{value}" for key, value
                       in sorted(autosut["fidelity_distribution"].items()))
            or "—"
        )
        evidence = autosut["evidence_path"]
        tier_label = tier_by_campaign.get(row["campaign_id"], "?")
        scope_label = scope_by_campaign.get(row["campaign_id"], "?")
        lines.append(
            "| " + " | ".join([
                f"`{row['campaign_id']}`",
                f"`{scope_label}`",
                f"`{tier_label}`",
                _format_list(frozen["hosts"]),
                _format_list(frozen["services"]),
                _format_list(frozen["credentials_declared"]),
                _format_list(autosut["hosts_applied"]),
                applications_display,
                _format_list(autosut["credentials_applied"]),
                _format_list(autosut["exposures_declared"]),
                ratio,
                str(autosut["caldera_operations"]),
                fidelity_display,
                f"`{evidence}`",
            ]) + " |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    if not GOLDEN_RUNS_PATH.exists():
        print(f"missing {GOLDEN_RUNS_PATH}; run "
              "scripts/curate_evidence.py --apply first", file=sys.stderr)
        return 1
    golden_data = json.loads(GOLDEN_RUNS_PATH.read_text(encoding="utf-8"))
    rows = []
    for entry in golden_data.get("campaigns", []):
        autosut_view = _read_autosut_view(entry)
        frozen_view = _read_frozen_view(entry["campaign_id"])
        rows.append(_row_for_campaign(entry["campaign_id"],
                                       autosut_view, frozen_view))
    OUTPUT_JSON.write_text(
        json.dumps({"campaigns": rows}, indent=2), encoding="utf-8")
    OUTPUT_MD.write_text(_render_markdown(rows), encoding="utf-8")
    print(f"[matrix] {len(rows)} golden campaigns")
    print(f"[matrix] markdown: {OUTPUT_MD.relative_to(PROJECT_ROOT)}")
    print(f"[matrix] json:     {OUTPUT_JSON.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
