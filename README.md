# AutoSUT Reproducibility Artifact

This anonymous repository contains the reviewer-facing artifact for
the environment-semantics measurement study. It is intentionally
venue-neutral: the repository name, files, and commands do not depend
on a specific conference track.

## Fast Reviewer Path

```bash
bash run_review_check.sh
```

The command reruns the measurement pipeline from frozen public input
bundles, regenerates figures and traceability outputs, and validates
numeric invariants. The study manuscript itself is intentionally
not included in this artifact; this repository is the independent
evidence and reproduction package.

Expected runtime on a laptop-class machine is about one minute once
Python and LaTeX dependencies are available. The command does not
require API keys, private data, paid services, Caldera, Docker, or VM
startup.

## Evidence Dashboard

The reviewer-facing static dashboard is
`autosut/release/dashboard/index.html`. If you view the file through
the 4open file browser, use the page's `Raw` link to render the HTML;
after downloading the ZIP, open the same file locally in a browser.
The dashboard summarizes the claim map, replay report, canonical
execution evidence, and raw CSV/JSON anchors without requiring a
server or external service.

## Full Docker Replay

```bash
cd autosut
python3 scripts/run_all_orchestrated_campaigns.py --preflight-only
python3 scripts/run_all_orchestrated_campaigns.py --clean-stale-autosut-containers
```

This path replays the implemented Docker-backed campaign/SUT pairs
and writes TSV/JSON reports under `release/`. It is slower than the
fast validation path and requires Docker; the preflight separates
infrastructure readiness from campaign failures before the long run.

## Heavier Optional VM Path

```bash
cd autosut
bash run_vm_backed_campaign.sh 0.cve_2021_41773
```

The optional VM-backed path is not required for the main measurement
claims. It is included to expose the declared campaign/SUT workflow
for reviewers who want to inspect the execution-facing substrate.

## Layout

- `autosut/`: artifact code, frozen bundles, release outputs, and reviewer scripts.
- `ARTIFACT_BOUNDARY.md`: what is included and intentionally excluded.
- `ARTIFACT_MANIFEST.md`: SHA-256 manifest for the staged repository.
