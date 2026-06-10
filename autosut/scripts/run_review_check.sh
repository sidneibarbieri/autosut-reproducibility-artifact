#!/bin/sh
# Release gate.
#
# Fail-fast validation of the AutoSUT public release surface. Exits with
# non-zero whenever any of the contracts is broken so reviewers and CI
# learn about issues immediately instead of after manual inspection.
#
# Contracts checked (each is an independent subcheck):
#
#   1. unit tests pass
#   2. release/golden_runs.json exists and parses
#   3. every campaign listed under golden_runs has a manifest.json,
#      summary.json, fidelity_report.json, and a non-zero technique count
#   4. every golden run reports 100% success
#   5. dashboard html is present and only references golden run paths
#   6. evidence under release/evidence/ contains no non-archived partial
#      run (i.e. _archive/ is the only place historical runs may live)
#   7. release/subdetermination_proof.json is present, the cve_2021_41773
#      executable witness ran (both variants), and the pivot_demo coincident
#      witness ran (OpenSSH<->Dropbear substitution executed, declared==executed)
#
# Run from the project root::
#
#     bash scripts/run_review_check.sh
#
set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

if [ -x "$PROJECT_ROOT/.venv/bin/python" ]; then
    PY="$PROJECT_ROOT/.venv/bin/python"
else
    PY="python3"
fi
GOLDEN_FILE="$PROJECT_ROOT/release/golden_runs.json"
DASHBOARD_HTML="$PROJECT_ROOT/release/dashboard/index.html"
step() {
    printf "[review-check] %s\n" "$*"
}

fail() {
    printf "[review-check] FAIL: %s\n" "$*" >&2
    exit 1
}

# ---------------------------------------------------------------------------
# 1. unit tests
# ---------------------------------------------------------------------------
step "running unit tests"
"$PY" -m pytest tests/ --tb=short -q >/dev/null \
    || fail "unit tests did not pass"

# ---------------------------------------------------------------------------
# 2. golden_runs.json present + parseable
# ---------------------------------------------------------------------------
step "validating golden_runs.json"
test -f "$GOLDEN_FILE" \
    || fail "release/golden_runs.json missing (run scripts/curate_evidence.py --apply)"
"$PY" -c "import json; json.load(open('$GOLDEN_FILE'))" \
    || fail "golden_runs.json is not valid JSON"

# ---------------------------------------------------------------------------
# 3 + 4. every golden has full evidence + 100% success
# ---------------------------------------------------------------------------
step "validating each golden run is complete and successful"
"$PY" - <<'PYEOF' || fail "golden run validation failed (see message above)"
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(".").resolve()
golden = json.loads((PROJECT_ROOT / "release" / "golden_runs.json").read_text())
campaigns = golden.get("campaigns", [])
if not campaigns:
    print("  no campaigns listed in golden_runs.json", file=sys.stderr)
    sys.exit(1)

def resolve_run_dir(entry):
    run_dir = PROJECT_ROOT / entry["evidence_path"]
    if run_dir.exists():
        return run_dir
    dashboard_run_dir = (
        PROJECT_ROOT
        / "release"
        / "dashboard"
        / "data"
        / "evidence"
        / Path(entry["evidence_path"]).name
    )
    return dashboard_run_dir

exit_code = 0
for entry in campaigns:
    run_dir = resolve_run_dir(entry)
    required = ["manifest.json", "summary.json", "fidelity_report.json"]
    for required_file in required:
        if not (run_dir / required_file).exists():
            print(f"  {entry['campaign_id']}: missing {required_file}",
                  file=sys.stderr)
            exit_code = 1
    manifest = json.loads((run_dir / "manifest.json").read_text())
    techniques = manifest.get("techniques", [])
    if not techniques:
        print(f"  {entry['campaign_id']}: zero techniques (0/0 run)",
              file=sys.stderr)
        exit_code = 1
        continue
    successful = sum(1 for tech in techniques if tech.get("status") == "success")
    if successful != len(techniques):
        print(f"  {entry['campaign_id']}: only {successful}/{len(techniques)} "
              "techniques succeeded; golden runs must be 100% success",
              file=sys.stderr)
        exit_code = 1
    teardown = run_dir / "sut" / "teardown.log"
    if not teardown.exists():
        print(f"  {entry['campaign_id']}: missing sut/teardown.log",
              file=sys.stderr)
        exit_code = 1
    composition_files = list((run_dir / "sut").glob("composition_*.json")) \
        if (run_dir / "sut").exists() else []
    if not composition_files:
        print(f"  {entry['campaign_id']}: missing sut/composition_*.json "
              "(every canonical campaign must declare its SUT realism)",
              file=sys.stderr)
        exit_code = 1
sys.exit(exit_code)
PYEOF

# ---------------------------------------------------------------------------
# 5. dashboard exists and does not point to non-golden evidence
# ---------------------------------------------------------------------------
step "validating dashboard exclusively cites golden runs"
test -f "$DASHBOARD_HTML" \
    || fail "release/dashboard/index.html missing (run scripts/build_reviewer_dashboard.py)"
"$PY" - <<'PYEOF' || fail "dashboard cites non-golden evidence (see message above)"
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(".").resolve()
dashboard_html = (PROJECT_ROOT / "release" / "dashboard" / "index.html"
                  ).read_text(encoding="utf-8")
golden = json.loads((PROJECT_ROOT / "release" / "golden_runs.json").read_text())
golden_run_ids = {entry["golden_run_id"]
                  for entry in golden.get("campaigns", [])}
referenced = set(re.findall(r"0\.[a-z_0-9]+_2026[0-9_]+", dashboard_html))
non_golden = sorted(referenced - golden_run_ids)
if non_golden:
    print("  dashboard references run IDs that are NOT golden:",
          file=sys.stderr)
    for run_id in non_golden:
        print(f"    {run_id}", file=sys.stderr)
    sys.exit(1)
PYEOF

step "validating dashboard evidence copy matches golden runs"
"$PY" - <<'PYEOF' || fail "dashboard evidence copy does not match golden runs"
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(".").resolve()
golden = json.loads((PROJECT_ROOT / "release" / "golden_runs.json").read_text())
golden_run_ids = {entry["golden_run_id"] for entry in golden.get("campaigns", [])}
evidence_dir = PROJECT_ROOT / "release" / "dashboard" / "data" / "evidence"
if not evidence_dir.exists():
    print("  dashboard data/evidence directory is missing", file=sys.stderr)
    sys.exit(1)
copied_run_ids = {path.name for path in evidence_dir.iterdir() if path.is_dir()}
missing = sorted(golden_run_ids - copied_run_ids)
extra = sorted(copied_run_ids - golden_run_ids)
if missing or extra:
    if missing:
        print("  dashboard evidence is missing golden runs:", file=sys.stderr)
        for run_id in missing:
            print(f"    {run_id}", file=sys.stderr)
    if extra:
        print("  dashboard evidence contains non-golden runs:", file=sys.stderr)
        for run_id in extra:
            print(f"    {run_id}", file=sys.stderr)
    sys.exit(1)
PYEOF

# ---------------------------------------------------------------------------
# 6. no non-archived partial runs in evidence/
# ---------------------------------------------------------------------------
step "validating evidence tree contains only golden runs at root"
"$PY" - <<'PYEOF' || fail "evidence root contains non-golden runs (see message above)"
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(".").resolve()
EVIDENCE_ROOT = PROJECT_ROOT / "release" / "evidence"
golden = json.loads((PROJECT_ROOT / "release" / "golden_runs.json").read_text())
golden_run_ids = {entry["golden_run_id"]
                  for entry in golden.get("campaigns", [])}
strays = []
for run_dir in sorted(EVIDENCE_ROOT.glob("0.*_2026*")):
    if not run_dir.is_dir():
        continue
    if run_dir.name not in golden_run_ids:
        strays.append(run_dir.name)
if strays:
    print("  evidence root has non-golden runs (move to _archive/):",
          file=sys.stderr)
    for run_id in strays:
        print(f"    {run_id}", file=sys.stderr)
    sys.exit(1)
PYEOF

# ---------------------------------------------------------------------------
# 7. Subdetermination proof artifact present + cve executable + pivot coincident
# ---------------------------------------------------------------------------
step "validating subdetermination proof artifact"
"$PY" - <<'PYEOF' || fail "subdetermination proof validation failed (see message above)"
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(".").resolve()
artifact = PROJECT_ROOT / "release" / "subdetermination_proof.json"
if not artifact.exists():
    print("  release/subdetermination_proof.json missing "
          "(run scripts/build_subdetermination_artifact.py)", file=sys.stderr)
    sys.exit(1)
proofs = json.loads(artifact.read_text()).get("proofs", {})
exit_code = 0
for campaign_id in ("0.cve_2021_41773", "0.apt41_dust"):
    proof = proofs.get(campaign_id)
    if proof is None:
        print(f"  {campaign_id}: proof missing from artifact", file=sys.stderr)
        exit_code = 1
        continue
    if not proof.get("invariant_fingerprint"):
        print(f"  {campaign_id}: empty invariant_fingerprint", file=sys.stderr)
        exit_code = 1
    if len(proof.get("variants", [])) < 2:
        print(f"  {campaign_id}: fewer than 2 variants", file=sys.stderr)
        exit_code = 1
if not proofs.get("0.cve_2021_41773", {}).get("executable"):
    print("  0.cve_2021_41773: executable proof is not true "
          "(regenerate with docker up)", file=sys.stderr)
    exit_code = 1
# Coincident witness: the informative free-region substitution (OpenSSH ->
# Dropbear) is itself executed. Existence needs >= 2 campaign-equivalent SUTs
# (canonical + >= 1 variant); both must run with declared == executed.
pivot = proofs.get("0.pivot_demo")
if pivot is None:
    print("  0.pivot_demo: coincident-witness proof missing from artifact",
          file=sys.stderr)
    exit_code = 1
else:
    if not pivot.get("invariant_fingerprint"):
        print("  0.pivot_demo: empty invariant_fingerprint", file=sys.stderr)
        exit_code = 1
    if len(pivot.get("variants", [])) < 1:
        print("  0.pivot_demo: no compatible variant", file=sys.stderr)
        exit_code = 1
    if not pivot.get("executable"):
        print("  0.pivot_demo: coincident witness is not executable "
              "(regenerate with docker up)", file=sys.stderr)
        exit_code = 1
sys.exit(exit_code)
PYEOF

step "ALL GATES PASSED"
