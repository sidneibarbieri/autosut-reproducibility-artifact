# Per-Campaign Isolated Orchestration

## Why this exists

The frozen `sticks-docker` workspace bootstraps every campaign's vulnerable
environment in a single shared container by running all `*_sutb.sh` and
`*_suta.sh` scripts at container startup. That design has three problems for
reproducibility:

1. **Contamination.** All campaigns share state. A package installed for one
   campaign affects what every other campaign sees.
2. **No isolation per fidelity declaration.** A campaign declared
   "exploit-pinned" against a specific CVE runs in the same MariaDB
   environment as a campaign with no CVE evidence at all.
3. **No teardown discipline.** The shared container persists between runs;
   there is no per-campaign clean state.

AutoSUT replaces that shared environment with a per-campaign tuple:

```
campaign C = (attacker_capabilities, sut_profile, cve_set, fidelity_declaration)
```

For each campaign in the catalog:

1. Select the SUT profile (Linux/Windows family, services required).
2. Instantiate a fresh, isolated environment.
3. Inject the vulnerabilities declared for the campaign.
4. Configure the attacker side with exactly the capabilities the campaign
   needs.
5. Execute the campaign end to end.
6. Capture per-technique evidence with fidelity stamps.
7. Tear down the environment.
8. Move to the next campaign with no state carried over.

This is what the paper calls **per-campaign declared lower-bound SUT**:
the environment is rebuilt from scratch for every campaign and the
fidelity stamps make explicit which steps are CVE-true (`adapted`) and
which are inspired surrogates (`inspired`).

## Tuple components

### Attacker capabilities (`AttackerProfile`)

A small, declarative profile that enumerates the tools the attacker side must
have available. Examples:

| Capability  | Concrete tools |
|-------------|----------------|
| `web_rce`   | curl, sshpass, optional metasploit |
| `db_dump`   | mysql/mariadb client, mysqldump |
| `pivot`     | ssh client, socat |
| `cert_gen`  | openssl |
| `rpc_rce`   | python3, requests |

A capability resolves to an install recipe (idempotent apt-get / pip
install). The orchestrator runs only the capabilities the current campaign
needs; nothing else.

### SUT profile (`SUTProfile`)

A declarative description of the target environment:

```yaml
sut_id: linux_web_db
base_image: ubuntu:22.04
services:
  - id: web
    package: nginx
    config: nginx_minimal.conf
  - id: db
    package: mariadb-server
    config: bind_all_with_seed_creds
  - id: ssh
    package: openssh-server
    config: password_auth_root_allowed
resources:
  memory_mb: 2048
  smp: 2
```

The SUT profile is environment-shaped, not CVE-shaped. CVEs are layered on
top by the CVE injector.

### CVE set / vulnerability injector (`CVEInjector`)

For each CVE the campaign declares, the injector chooses one of three
fidelity levels and records the choice:

- **`adapted_real`**: install the actual vulnerable software at the declared
  version. Allowed only when the software is free and installable. Example:
  Ray ML 2.6.3 for CVE-2023-48022.
- **`adapted_surrogate`**: install a minimal HTTP/RPC service that mimics the
  vulnerable endpoint with equivalent semantics (e.g. a Flask service exposing
  unauthenticated command execution where the real product would).
- **`inspired`**: no vulnerable software is installed; the technique sequence
  is exercised against a generic primitive (open SSH with weak password,
  exposed MariaDB with seeded credentials). The campaign run is still
  reproducible, but the CVE itself is not exploited.

Every fidelity choice is **declared in the manifest** so reviewers can audit.

### Fidelity declaration

Each campaign run emits, per technique:

```json
{
  "technique_id": "T1190",
  "campaign": "0.shadowray",
  "cve": "CVE-2023-48022",
  "fidelity": {
    "declared": "exploit-pinned",
    "executed": "adapted_real",
    "evidence": ["target/ray_dashboard_rce.log", "target/cmd_output.txt"]
  }
}
```

The triplet (`declared`, `executed`, `evidence`) is the auditable surface.
A reviewer can spot-check whether the executed fidelity matches what the
paper claimed.

## Orchestrator interface

```python
class CampaignOrchestrator:
    def run_campaign(self, campaign_id: str) -> RunResult:
        sut = self.sut_catalog.resolve(campaign_id)
        attacker = self.attacker_catalog.resolve(campaign_id)
        cve_set = self.campaign_catalog.cves_for(campaign_id)

        with self.environment.bring_up(sut, attacker) as env:
            self.injector.inject(env, cve_set)
            attacker_caps = self.attacker_installer.install(env, attacker)
            result = self.executor.run(env, campaign_id)
            self.evidence.capture(env, result)
        # environment is torn down on context exit; next campaign starts fresh
        return result
```

Each subsystem is replaceable: `Environment` may be Docker, QEMU/HVF, or
Vagrant. The orchestrator does not care; it only requires the interface.

## Evidence layout

```
release/evidence/<campaign>_<timestamp>/
├── manifest.json            # tuple + fidelity per technique
├── summary.json             # roll-up consumed by EXPERIMENT_LOG
├── sut/
│   ├── setup.log            # SUT instantiation transcript
│   ├── cve_injection.log    # per-CVE install transcript
│   └── teardown.log         # teardown transcript
├── attacker/
│   ├── install.log
│   └── exec.log
├── techniques/
│   ├── T1190.log
│   ├── T1059.004.log
│   └── ...
└── provenance.json          # git commit, host info, run params
```

`manifest.json` is the contract: it carries the tuple AND the per-technique
fidelity. `EXPERIMENT_LOG.jsonl` aggregates manifests across runs.

## Comparison with the frozen workspace

| Concern | Frozen `sticks-docker` | AutoSUT orchestrator |
|---------|------------------------|----------------------|
| Environment per campaign | shared container | isolated per run |
| Fidelity declaration | none (all "inspired") | per-CVE, per-technique |
| Teardown | none (stack persists) | mandatory between campaigns |
| Real CVE install | no | yes when software is free |
| Evidence | one combined log | per-technique, per-tuple |
| Reproducibility contract | "run docker-compose up" | per-campaign manifest |

## Phasing

This document specifies the **target architecture**. Implementation in this
checkout is incremental:

1. **Phase 1 (this release).** Implement the orchestrator core, the SUT
   catalog, and one real-CVE campaign end to end (`0.shadowray` with real Ray
   ML installation). Reviewers can re-execute that single campaign and
   inspect the per-run manifest, rubric, and composition evidence. This is
   bounded replay of the environment-conditioned behaviors declared by the
   campaign, not historical reconstruction of the original intrusion.
2. **Phase 2.** Add adapted-surrogate fallback for CVEs without free
   reproducible software; populate the catalog with the remaining 7
   campaigns.
3. **Phase 3.** Promote the orchestrator to be the canonical entry point of
   `run_vm_backed_campaign.sh`.

The paper claims hold today on the data-only path (`run_review_check.sh`);
the orchestrator strengthens the secondary "VM-backed realism path" without
changing any paper numbers.

## Substrate hierarchy (S12)

AutoSUT separates **orchestration semantics** (tuple, manifest, fidelity
rubric, Caldera dispatch) from **execution substrate**. The same campaign
JSON drives any of three backends — selected per SUT profile via
``backend: "docker" | "qemu" | "tart"``:

| Tier | Backend | When to use | Cold-start cost | Apple Silicon |
|---|---|---|---|---|
| Canonical | ``DockerEnvironment`` | reviewer-facing default; portable, low cost | ~2 s | yes (Colima) |
| Extended realism | ``QEMUEnvironment`` (Vagrant + QEMU on Apple Silicon, Vagrant + libvirt on Linux) | real kernel boundary, real virtual NIC, real filesystem | ~30–60 s (after box cached) | yes (HVF) |
| Experimental | ``TartEnvironment`` (Apple Virtualization.framework) | fast-path on Apple Silicon for lab work | ~5–10 s | only |

The canonical Docker path is the reviewer-recommended default. The QEMU
path provides paridade with the frozen ``sticks/Vagrantfile`` and enables
research claims that require strictly stronger isolation than a container.
Tart is offered for development convenience and is not the
artifact-evaluation recommendation (avoids the "Apple-only artifact"
critique).

All three backends implement the same
``scripts/orchestrator/environment_base.EnvironmentBackend`` ABC:

```python
class EnvironmentBackend(ABC):
    backend_name: str
    @classmethod
    @abstractmethod
    def bring_up(cls, sut, run_dir): ...
    @abstractmethod
    def run_shell(self, command, log_name=None, timeout=600): ...
    @abstractmethod
    def teardown(self): ...
```

The orchestrator never reaches into backend internals; the executor and
Caldera dispatch see only the abstract contract. This means a campaign
audited on Docker is reproducible on QEMU without any campaign-level
changes — the substrate is selected by the SUT profile.

## MITRE Caldera integration (S7–S9)

The frozen `sticks-docker` workspace mentioned Caldera but never drove a
real C2 channel. AutoSUT runs the **official MITRE Caldera 5.2.0** container
(`ghcr.io/mitre/caldera:latest`) as `autosut-caldera` and uses three integration
layers:

1. **Provenance snapshot (S7).** Every `run_campaign` call probes the live
   Caldera instance (URL, API health, server version, agent count, ability
   count) and writes the snapshot into `release/evidence/<run>/provenance.json`.
   A reviewer can audit whether the artifact was generated against a real
   Caldera or an empty one.

2. **Atomic Red Team annotation (S8).** Every `TechniqueOutcome` is matched
   against Caldera's ability index by `technique_id`. When Caldera ships an
   ability for the technique, the outcome carries
   `caldera_ability_id` + `caldera_ability_name` even if AutoSUT used its own
   recipe — making the manifest cross-referenceable against the canonical
   MITRE ART corpus. When the local recipe declared `real_controlled` *and*
   an ART ability exists, `executed_mode` is promoted to `atomic_red_team`.

3. **Caldera-driven dispatch (S9).** Campaigns can opt techniques into
   `expected_mode: caldera_driven`. The orchestrator then:

   - downloads the matching sandcat binary (Linux x86_64 or Linux ARM64)
     from Caldera's `/file/download` endpoint;
   - installs and starts the agent inside the SUT container, pointed at the
     Caldera C2 over the shared Docker bridge network;
   - waits until the paw registers in the `red` group;
   - creates a one-off Caldera adversary whose `atomic_ordering` is the
     single matching ability_id;
   - starts a Caldera operation under the **atomic planner**;
   - waits for the operation to finish and pulls the report;
   - persists the full operation report and the per-link stdout/stderr under
     `release/evidence/<run>/caldera/`;
   - records `executed_mode=caldera_driven` (when the link returns
     status=0), `caldera_driven` + `status=failure` (when Caldera was
     contacted but the ability rejected), or `naive_simulated` (when no
     Linux ability exists for the technique).

   The `0.caldera_linux_demo` campaign exercises six self-contained Linux
   ART abilities end to end and is the canonical S9 reference.

```
release/evidence/<run>/caldera/
├── agent_<paw>.txt                    # registration breadcrumb
├── T<id>_<operation_id>_report.json   # full Caldera op report
└── T<id>_<link_id>.log                # per-ability stdout/stderr
```

This trio (provenance → annotation → dispatch) means every claim about
"adversary emulation backed by MITRE Caldera" in the paper is auditable
against on-disk evidence produced by Caldera itself.
