# AutoSUT Campaign Coverage Matrix

Generated: `2026-05-31T22:40:12`

Compares the eight legacy Docker campaigns against the current AutoSUT artifact.

**Status definitions**
- `COMPLETE` — zero failed techniques, evidence generated, provenance consistent
- `PARTIAL` — runs but at least one technique fails or evidence is incomplete
- `MISSING` — campaign or SUT profile absent, or no execution recorded

## Summary

| Metric | Value |
|---|---|
| Legacy campaigns | 8 |
| COMPLETE | 8 |
| PARTIAL | 0 |
| MISSING | 0 |

## Matrix

| Legacy Campaign | AutoSUT ID | Campaign File | SUT Profile | Docker Steps | AutoSUT Steps | Executor Coverage | Status |
|---|---|:---:|:---:|---:|---:|---:|:---:|
| APT41 DUST | `0.apt41_dust` | ✓ | ✓ | 24 | 23 | 100% | **COMPLETE** |
| C0010 | `0.c0010` | ✓ | ✓ | 10 | 9 | 100% | **COMPLETE** |
| C0026 | `0.c0026` | ✓ | ✓ | 7 | 6 | 100% | **COMPLETE** |
| CostaRicto | `0.costaricto` | ✓ | ✓ | 11 | 10 | 100% | **COMPLETE** |
| Operation MidnightEclipse | `0.operation_midnighteclipse` | ✓ | ✓ | 18 | 17 | 100% | **COMPLETE** |
| Outer Space | `0.outer_space` | ✓ | ✓ | 9 | 8 | 100% | **COMPLETE** |
| Salesforce Data Exfiltration | `0.salesforce_data_exfiltration` | ✓ | ✓ | 19 | 18 | 100% | **COMPLETE** |
| ShadowRay | `0.shadowray` | ✓ | ✓ | 11 | 10 | 100% | **COMPLETE** |

## Methodological Divergences

### APT41 DUST (`0.apt41_dust`)

- docker_techniques=24 includes redundant sub-steps merged into 13 canonical ATT&CK techniques
- Web-service C2 (T1102) and infrastructure acquisition (T1583.006) simulated as inspired; no live external traffic

### C0010 (`0.c0010`)

- Resource-development steps remain inspired; no live external provider interaction

### C0026 (`0.c0026`)

- DNS resolution override adapted to lab-only local resolver path

### CostaRicto (`0.costaricto`)

- Multi-hop proxy and external remote services remain inspired; no live C2 infrastructure

### Outer Space (`0.outer_space`)

- Satellite-themed C2 infrastructure acquisition simulated as inspired

### Salesforce Data Exfiltration (`0.salesforce_data_exfiltration`)

- SaaS API calls to Salesforce simulated as inspired; no live tenant

### ShadowRay (`0.shadowray`)

- Ray Dashboard (CVE-2023-48022) is exposed as a declared step-conditioned SUT overlay immediately before T1190, not hidden inside the base image. The overlay provisions a minimal unauthenticated HTTP stub on port 8265 that responds to /api/version and /api/jobs/ like a Ray cluster with auth disabled. If the overlay is absent, the executor still falls back to provisioning the same boundary inline inside the target VM. The boundary exercised (unauthenticated job-submission API) is methodologically equivalent to CVE-2023-48022 exploitation.


## Latest Execution Results

| AutoSUT ID | Status | Successful | Failed | Total | Success Rate |
|---|:---:|---:|---:|---:|---:|
| `0.apt41_dust` | **COMPLETE** | 10 | 0 | 10 | 100.0% |
| `0.c0010` | **COMPLETE** | 9 | 0 | 9 | 100.0% |
| `0.c0026` | **COMPLETE** | 6 | 0 | 6 | 100.0% |
| `0.costaricto` | **COMPLETE** | 10 | 0 | 10 | 100.0% |
| `0.operation_midnighteclipse` | **COMPLETE** | 17 | 0 | 17 | 100.0% |
| `0.outer_space` | **COMPLETE** | 8 | 0 | 8 | 100.0% |
| `0.salesforce_data_exfiltration` | **COMPLETE** | 18 | 0 | 18 | 100.0% |
| `0.shadowray` | **COMPLETE** | 3 | 0 | 3 | 100.0% |
