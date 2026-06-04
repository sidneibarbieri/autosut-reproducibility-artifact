# Environment Provenance

- Generated at: `2026-06-03T22:54:45`
- Campaigns measured: `19`
- Total tagged SUT elements: `133`
- Policy: 3-category hybrid (`corpus_supported` / `autosut_concretized` / `analyst_authored`).

Of the **133** concrete SUT elements materialised across **19** campaign SUT profiles, **24.1%** is anchored in the CTI corpus, **17.3%** is an AutoSUT concretization of an under-specified corpus signal, and **58.6%** is an explicit analyst lab choice the corpus does not constrain.

## Dimension x Source

Each tagged element belongs to exactly one dimension. This table is the environment-gap measurement: it shows, dimension by dimension, how much of the executable environment public cyber knowledge actually supports.

| Dimension | Corpus | AutoSUT | Analyst | Total |
|---|---:|---:|---:|---:|
| Platform | 25 | 0 | 0 | 25 |
| Software | 1 | 0 | 19 | 20 |
| Vulnerability | 2 | 1 | 0 | 3 |
| Credentials | 1 | 21 | 0 | 22 |
| Exposures | 3 | 1 | 24 | 28 |
| Artifacts | 0 | 0 | 32 | 32 |
| Topology | 0 | 0 | 3 | 3 |
| **All** | 32 (24.1%) | 23 (17.3%) | 78 (58.6%) | **133** |

## Per-Campaign Breakdown

| Campaign | Elements | Corpus | AutoSUT | Analyst |
|---|---:|---:|---:|---:|
| `0.shadowray` | 6 | 4 (66.7%) | 0 (0.0%) | 2 (33.3%) |
| `0.c0010` | 8 | 1 (12.5%) | 1 (12.5%) | 6 (75.0%) |
| `0.c0011` | 7 | 1 (14.3%) | 1 (14.3%) | 5 (71.4%) |
| `0.c0012` | 4 | 1 (25.0%) | 1 (25.0%) | 2 (50.0%) |
| `0.c0013` | 6 | 1 (16.7%) | 1 (16.7%) | 4 (66.7%) |
| `0.c0015` | 6 | 1 (16.7%) | 1 (16.7%) | 4 (66.7%) |
| `0.c0017` | 5 | 1 (20.0%) | 1 (20.0%) | 3 (60.0%) |
| `0.c0026` | 6 | 1 (16.7%) | 1 (16.7%) | 4 (66.7%) |
| `0.apt41_dust` | 11 | 1 (9.1%) | 1 (9.1%) | 9 (81.8%) |
| `0.apt41_dust_full` | 6 | 1 (16.7%) | 1 (16.7%) | 4 (66.7%) |
| `0.costaricto` | 9 | 1 (11.1%) | 1 (11.1%) | 7 (77.8%) |
| `0.outer_space` | 9 | 1 (11.1%) | 1 (11.1%) | 7 (77.8%) |
| `0.operation_midnighteclipse` | 5 | 3 (60.0%) | 1 (20.0%) | 1 (20.0%) |
| `0.salesforce_data_exfiltration` | 6 | 1 (16.7%) | 4 (66.7%) | 1 (16.7%) |
| `0.caldera_linux_demo` | 7 | 1 (14.3%) | 1 (14.3%) | 5 (71.4%) |
| `0.fin6_emulation` | 7 | 1 (14.3%) | 1 (14.3%) | 5 (71.4%) |
| `0.dmz_segmentation_demo` | 13 | 4 (30.8%) | 3 (23.1%) | 6 (46.2%) |
| `0.pivot_demo` | 7 | 3 (42.9%) | 2 (28.6%) | 2 (28.6%) |
| `0.cve_2021_41773` | 5 | 4 (80.0%) | 0 (0.0%) | 1 (20.0%) |

## How to read this

- **Corpus** = the value is anchored in CTI/NVD/ATT&CK evidence: a CVE-pinned product+version, the disclosed CVE itself, the documented exploit surface/port, or the OS platform family (an ATT&CK `x_mitre_platforms` field).
- **AutoSUT** = AutoSUT concretized an under-specified corpus signal: the corpus implies *a* usable credential exists (valid-accounts / brute-force), AutoSUT picks the literal pair; or a named-product surrogate with no disclosed CVE.
- **Analyst** = no corpus signal; pure lab construction: generic inherited services (the campaign needs *an* affordance, not that specific product), topology zones, and decoy files.
- Provenance is **counted, never computed**: the aggregator only tallies tags an analyst set in `catalog.py`. The sole derived tags are definitional (a real CVE id *is* corpus evidence; an OS family *is* an ATT&CK platform).
