# Artifact Guide

## Purpose

This document defines the public-facing artifact path for the current
repository state.

## Canonical Commands

```bash
bash artifact/setup.sh
bash artifact/run.sh
bash artifact/validate.sh
```

## Direct Commands

```bash
python3 scripts/run_campaign.py --campaign 0.c0011
python3 scripts/generate_tables.py
```

## Guarantees

- Campaign loading supports both canonical YAML and compatibility JSON.
- The smoke path writes structured evidence to `release/evidence/`.
- Table generation writes LaTeX outputs to `results/tables/`.

## Non-Guarantees

- Full-corpus success is not currently guaranteed.
- Optional multi-VM helpers may report degraded state depending on the local
  environment.
- Historical frozen results are retained for comparison and paper traceability,
  not as a substitute for live validation.

