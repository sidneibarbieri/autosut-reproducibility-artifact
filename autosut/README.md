# AutoSUT Reproducibility Artifact

AutoSUT is a reproducibility package for controlled ATT&CK-aligned campaign execution
and for measuring the environment semantics gap in structured CTI.
The repository contains:

- campaign definitions,
- SUT profiles,
- executor implementations,
- lab provisioning helpers,
- evidence and table-generation scripts.

This repository currently has four reproducibility layers:

- a study-claim validation path in `run_review_check.sh`;
- a repository-local minimal working example in `artifact/` and
  `scripts/run_campaign.py`;
- an orchestrated campaign replay path in
  `scripts/run_all_orchestrated_campaigns.py`;
- a provider-aware VM-backed path in `run_vm_backed_campaign.sh` and
  `scripts/run_lab_campaign.py` for campaigns that need concrete lab
  infrastructure.

The fastest top-level validation path is
`bash run_review_check.sh`. The `artifact/` wrappers remain the smallest
repository-local execution example.

The static evidence dashboard is `release/dashboard/index.html`. After a ZIP
download or clone, the lowest-friction local view is:

```bash
cd release/dashboard
python3 -m http.server 8765 --bind 127.0.0.1
```

Then open `http://127.0.0.1:8765/` in a browser. Opening `index.html` directly
also works after extraction. The dashboard is designed as the reviewer-first
visual map of claims, replay reports, canonical evidence, and raw CSV/JSON
anchors.

The public repository scope intended for GitHub publication and artifact
distribution is defined in `PUBLIC_REPOSITORY_SCOPE.md`.

The repository also ships a deterministic downstream report,
`results/CVE_RESOLUTION_CANDIDATES.md`, that asks a narrower question than the
main study itself: when a published campaign already carries CVE evidence, which
pairs can currently be turned into candidate SUT targets with explicit package
or product bindings? This report is an artifact extension, not a broader study
claim. It is also not an exhaustive crawl of the `apt` or `pip` ecosystems:
it only resolves the ATT&CK-linked campaign/CVE slice already present in the
artifact through curated, source-backed rules. In the current public artifact,
the automatic path is one `pip` case (`ShadowRay / CVE-2023-48022 -> ray`) and
zero automatic `apt` cases.

It also ships `results/INFRA_AUTOMATION_COVERAGE.md`, which makes the current
IaC/SUT automation boundary explicit per campaign: runtime VM set, target-host
topology, automatically applied base weaknesses, declared step overlays, and
latest evidence status.

It also ships `results/COMPATIBILITY_RULE_SURFACE.md`, which exposes the exact
deterministic keywords and regexes behind the CF/VMR/ID compatibility rules
used by the measurement pipeline.

It also ships `measurement/sut/scripts/results/audit/compatibility_validation_sample.csv`,
a 36-row stratified adjudication packet for the CF/VMR/ID taxonomy. The manual
label columns are intentionally blank in the submitted artifact; after an
independent reviewer fills `manual_expected_class`, `manual_verdict_match`,
`manual_notes`, and `reviewer`, rerun
`python3 measurement/sut/scripts/evaluate_compatibility_validation.py` to
regenerate the agreement summary, confusion table, disagreements file, and
Cohen's kappa. Until those labels are added, the packet is a construct-audit
surface rather than a completed inter-rater agreement result.

The current published subset is still conservative: the shipped campaign/SUT
pairs currently use single target-host examples, even though the IaC path is
designed to lift multi-host topologies when a declared SUT profile requires
them.

## Execution Paths at a Glance

| Path | Command | Required tools | Recommended host | Typical role |
| --- | --- | --- | --- | --- |
| Fast study-claim validation | `bash run_review_check.sh` | `python3` | commodity laptop/desktop | revalidate released values and synthesized outputs |
| Minimal working example | `bash artifact/setup.sh && bash artifact/run.sh && bash artifact/validate.sh` | `python3`, `venv` | commodity laptop/desktop | smallest repository-local execution trace |
| Orchestrated campaign replay | `python3 scripts/run_all_orchestrated_campaigns.py --preflight-only` then `python3 scripts/run_all_orchestrated_campaigns.py` | `python3`, `docker` | Docker-capable host | sequentially replay all implemented campaign/SUT pairs and write TSV/JSON status reports |
| VM-backed realism | `bash run_vm_backed_campaign.sh 0.c0011` | `python3`, `vagrant`, `qemu` or `libvirt` | 8 CPU cores, 16 GB RAM, 25 GB free disk recommended | cold-start campaign/SUT replay on declared lab infrastructure |

The first two paths are the fastest validation contract. The orchestrated
Docker path is the reviewer-facing full replay of implemented campaign/SUT
pairs. The VM-backed path is honest but heavier: on a cold start it may spend
most of its time bootstrapping guests, installing packages, and bringing
Caldera-related lab services up before the campaign itself runs.
By default, the VM-backed wrapper restores tracked study-facing summaries after
teardown and removes runtime-only lab byproducts. Use
`--persist-derived-state` only when you explicitly want to keep regenerated
summaries or local SUT reports in the checkout.
These paths are local: they do not call external services and do not
require API keys or cloud credits.

## Fast Validation

```bash
bash run_review_check.sh
```

This path reruns the measurement pipeline, refreshes the released study-facing
outputs, and checks that the synthesized values remain internally consistent.
If the required Python packages are not already available, the wrapper creates
and reuses a repo-local `.venv` automatically.
On a cold machine, that first bootstrap may download the packages listed in
`requirements.txt`.

It is the recommended first step for anyone who wants to confirm the study
claims without provisioning VMs.

## Minimal Working Example

```bash
bash artifact/setup.sh
bash artifact/run.sh
bash artifact/validate.sh
```

`artifact/setup.sh` prepares the repo-local `.venv`; the subsequent wrappers
reuse that interpreter automatically and do not require manual activation.

Equivalent direct commands:

```bash
.venv/bin/python3 scripts/run_campaign.py --campaign 0.c0011
.venv/bin/python3 scripts/generate_tables.py
```

To list campaigns:

```bash
.venv/bin/python3 scripts/run_campaign.py
```

This path is the smallest end-to-end execution example in the public checkout.
It should be preferred over the VM-backed path when the goal is simply to
confirm that the repository runs and emits structured evidence correctly.

## Full Orchestrated Campaign Replay

Use the preflight first. It checks Docker and the Caldera C2 dependency before
starting a long replay, so an infrastructure problem is reported before it
creates misleading campaign failures.

```bash
python3 scripts/run_all_orchestrated_campaigns.py --preflight-only
```

Run one campaign when debugging:

```bash
python3 scripts/run_all_orchestrated_campaigns.py --campaign 0.c0013
```

Run the full implemented campaign suite:

```bash
python3 scripts/run_all_orchestrated_campaigns.py
```

If a previous local batch was interrupted, first remove only stale AutoSUT
campaign containers:

```bash
python3 scripts/run_all_orchestrated_campaigns.py --clean-stale-autosut-containers --preflight-only
```

The runner writes `release/orchestrated_replay_<timestamp>.tsv` and a matching
JSON report after each campaign. This makes partial long runs auditable instead
of losing all progress when a host, Docker, or Caldera issue interrupts the
batch. By default, known slow campaigns run last so the reviewer gets early
feedback from faster campaigns; use `--catalog-order` to preserve catalog order.

## Canonical Entry Points

- `run_review_check.sh`: top-level study-claim validation path
- `run_vm_backed_campaign.sh`: top-level VM-backed realism wrapper for one campaign
- `artifact/setup.sh`: environment and dependency check
- `artifact/run.sh`: canonical smoke execution for one representative campaign
- `artifact/validate.sh`: output validation for the smoke path
- `artifact/teardown.sh`: cleanup helper
- `scripts/run_all_orchestrated_campaigns.py`: Docker-backed full campaign replay with preflight and TSV/JSON reports
- `scripts/run_campaign.py`: campaign execution
- `scripts/run_lab_campaign.py`: canonical VM-backed orchestration for one campaign/SUT pair
- `scripts/generate_tables.py`: LaTeX table generation
- `scripts/up_lab.sh`: provider-aware lab provisioning and SUT application
- `scripts/destroy_lab.sh`: provider-aware lab teardown
- `caldera_manager.py`: optional host-side Caldera or mock service manager

## What Is Currently Guaranteed

- `bash run_review_check.sh` revalidates the released study-facing outputs from
  a clean checkout.
- The released reports include a deterministic campaign/CVE concretization view
  in `results/CVE_RESOLUTION_CANDIDATES.md` and
  `results/cve_resolution_candidates.json`.
- The released reports include an infrastructure/SUT automation coverage view
  in `results/INFRA_AUTOMATION_COVERAGE.md` and
  `results/infra_automation_coverage.json`.
- The released reports include a compatibility-rule audit surface in
  `results/COMPATIBILITY_RULE_SURFACE.md` and
  `results/compatibility_rule_surface.json`.
- The compatibility-validation packet is regenerated and evaluated as
  `pending_manual_labels` unless an independent reviewer supplies manual labels.
- The repository can list available campaigns.
- The canonical runner can execute campaign definitions from both:
  - `data/campaigns/*.yml`
  - `campaigns/*.json`
- The baseline smoke path writes structured evidence under `release/evidence/`.
- Table generation works from the repository state and writes to `results/tables/`.
- ATT&CK technique/tactic metadata in the published JSON corpus is audited against
  `data/stix/enterprise-attack.json`.
- The VM-backed path resolves topology from each campaign's SUT profile, brings
  up the required VMs, applies the declared base SUT profile, conditionally
  overlays step-specific SUT deltas for selected techniques, runs the selected
  campaign, refreshes evidence/state reports, and tears the lab down when
  requested through `scripts/run_lab_campaign.py`.
- The published campaign/SUT pairs currently exercise single target-host
  topologies; multi-host support exists at the IaC layer and is reported
  explicitly in `results/INFRA_AUTOMATION_COVERAGE.md` rather than implied.
- Declared SUT profiles remain the source of truth for host count, topology,
  and automatically applied weaknesses; the runner does not invent new runtime
  topology or vulnerability state online.

## Known Limits

- The smoke path remains the canonical validation contract because it is fast,
  platform-light, and easy to verify from a clean checkout.
- VM-backed execution is heavier than the smoke path and should be interpreted
  campaign by campaign rather than as a promise of universal historical replay.
- Strict campaign/SUT pair validation is tracked separately from mere profile
  presence in `results/CORPUS_STATE.md` and
  `results/CAMPAIGN_SUT_FIDELITY_MATRIX.md`.
- Fidelity labels such as `faithful`, `adapted`, and `inspired` remain part of
  the execution contract; a green run does not imply historical or observational
  equivalence to the original intrusion.
- Optional multi-VM utilities are useful for development, but they are not the
  only supported validation path.
- The optional QEMU path depends on a Caldera-compatible service being reachable
  on the Mac host at `localhost:8888`.
- When the VM-backed path provisions a Caldera node inside the lab, that node is
  still part of lab readiness rather than the campaign planner itself; the
  campaign steps remain orchestrated by the AutoSUT runner.
- `python3 caldera_manager.py start-mock` can be used to validate VM-to-host
  connectivity without claiming equivalence to a real Caldera deployment.
- Run-generated evidence is regenerated under `release/evidence/` when the
  smoke path or VM-backed path is run.
- The CVE concretization report is regenerated deterministically from
  measured ATT&CK outputs plus curated CVE rules; it does not synthesize
  exploits or infer target products online, and it should not be read as a
  complete measurement of the `apt` or `pip` package ecosystems.
- Public release/results reports are shipped in regenerated, reviewer-facing
  form from this checkout rather than as opaque local runtime traces.
- The current GitHub handoff may ship representative VM-backed evidence for a
  subset of campaigns; broader corpus and pair-validation coverage remain
  visible in the synthesized reports without pretending that every historical
  cold-start run is embedded in the checkout.

## Validation Notes

- Start with `bash run_review_check.sh`.
- Use the `artifact/` path when you want the smallest repository-local
  execution example rather than the full study-facing validation path.
- Use `python3 scripts/run_campaign.py` to inspect the available campaign IDs in
  the current checkout.
- Use `python3 scripts/generate_corpus_state.py` to inspect the current published
  versus executable corpus state.
- Use `cat results/CAMPAIGN_SUT_FIDELITY_MATRIX.md` to see which campaign/SUT
  pairs currently pass strict validation and what their latest evidence looks
  like.
- Use `cat results/CVE_RESOLUTION_CANDIDATES.md` to inspect which
  campaign-linked CVEs currently resolve to an open-package or product-bound
  SUT candidate in the public artifact.
- Use `cat results/COMPATIBILITY_RULE_SURFACE.md` to inspect the exact
  deterministic keyword and regex surface behind the CF/VMR/ID rules.
- Use `cat results/INFRA_AUTOMATION_COVERAGE.md` to inspect the current
  automation boundary for VM topology, target-host count, base weaknesses, and
  step-conditioned overlays per campaign/SUT pair.
- If you want to inspect lab state, use:

```bash
python3 multi_vm_manager_2vm.py status
```

- If you want the optional lab environment:

```bash
bash run_vm_backed_campaign.sh 0.c0011
bash run_vm_backed_campaign.sh 0.shadowray
```

## Repository Hygiene

- `scripts/sanitize_repo.sh` performs dry-run sanitization by default.
- `scripts/check_public_surface.py` audits the public repository
  surface for stale content and publication blockers.
- `release/` contains synthesized outputs plus runtime-generated evidence when
  the included workflows are executed.

## Primary Files

- `src/loaders/campaign_loader.py`
- `src/runners/campaign_runner.py`
- `src/executors/executor_registry.py`
- `data/sut_profiles/`
- `campaigns/`
- `artifact/`
