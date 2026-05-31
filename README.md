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
numeric invariants. If a manuscript tree exists in a maintainer
workspace, the same verifier can also synchronize paper macros; the
submitted paper itself is intentionally not included in this artifact.

Expected runtime on a laptop-class machine is about one minute once
Python and LaTeX dependencies are available. The command does not
require API keys, private data, paid services, Caldera, Docker, or VM
startup.

## Heavier Optional Path

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
