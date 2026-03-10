#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV="$SCRIPT_DIR/venv"
FOSSA_RESULTS="$SCRIPT_DIR/fossa-results.json"
SEMGREP_RESULTS="$SCRIPT_DIR/semgrep-results.json"

echo "============================================================"
echo "  OSS SCAN TEST - FOSSA + SEMGREP"
echo "============================================================"
echo ""

# Activate venv
source "$VENV/bin/activate"

# ----------------------------------------------------------------
# FOSSA / pip-licenses
# ----------------------------------------------------------------
echo "[1/2] Running licence scan..."

FOSSA_OK=false
PIP_LIC_OK=false

# Try fossa analyze --output first
FOSSA_BIN="./fossa"
[ ! -x "$FOSSA_BIN" ] && FOSSA_BIN="fossa"

if command -v "$FOSSA_BIN" &>/dev/null || [ -x "$FOSSA_BIN" ]; then
    echo "  → fossa CLI found, running analyze --output ..."
    set +e
    "$FOSSA_BIN" analyze --output 2>/dev/null > "$FOSSA_RESULTS.raw"
    FOSSA_EXIT=$?
    set -e
    if [ $FOSSA_EXIT -eq 0 ] && [ -s "$FOSSA_RESULTS.raw" ]; then
        # fossa --output emits ANSI + JSON mix; extract JSON lines
        python3 - <<'PYEOF' "$FOSSA_RESULTS.raw" "$FOSSA_RESULTS"
import sys, json, re

raw_file = sys.argv[1]
out_file  = sys.argv[2]
with open(raw_file) as f:
    text = f.read()

# strip ANSI
clean = re.sub(r'\x1b\[[0-9;]*m', '', text)

# find first { or [ to locate JSON start
start = min(
    (clean.find(c) for c in ['{','['] if clean.find(c) != -1),
    default=-1
)
if start == -1:
    print("FOSSA output contained no JSON", file=sys.stderr)
    sys.exit(1)

data = json.loads(clean[start:])
with open(out_file, 'w') as f:
    json.dump(data, f, indent=2)
print(f"  FOSSA JSON written to {out_file}")
PYEOF
        FOSSA_OK=true
    else
        echo "  → fossa analyze exited $FOSSA_EXIT or produced no output; falling back to pip-licenses."
    fi
else
    echo "  → fossa CLI not found; using pip-licenses fallback."
fi

# pip-licenses fallback
if [ "$FOSSA_OK" = false ]; then
    if ! python3 -c "import piplicenses" &>/dev/null; then
        pip install --quiet pip-licenses
    fi
    echo "  → Running pip-licenses..."
    pip-licenses --format=json --with-urls --output-file="$FOSSA_RESULTS"
    PIP_LIC_OK=true
    echo "  pip-licenses JSON written to $FOSSA_RESULTS"
fi

# ----------------------------------------------------------------
# SEMGREP
# ----------------------------------------------------------------
echo ""
echo "[2/2] Running Semgrep..."

SEMGREP_RULESETS="p/python p/owasp-top-ten .semgrep.yml"

set +e
semgrep scan \
    --config p/python \
    --config p/owasp-top-ten \
    --config .semgrep.yml \
    --json \
    --output "$SEMGREP_RESULTS" \
    app.py \
    2>/dev/null
SEMGREP_EXIT=$?
set -e

# semgrep exits 1 when findings exist — that's expected
if [ -s "$SEMGREP_RESULTS" ]; then
    echo "  Semgrep results written to $SEMGREP_RESULTS"
else
    echo "  WARNING: Semgrep produced no output (exit $SEMGREP_EXIT)"
    echo '{"results":[],"errors":[]}' > "$SEMGREP_RESULTS"
fi

# ----------------------------------------------------------------
# HUMAN-READABLE SUMMARY
# ----------------------------------------------------------------
echo ""
echo "============================================================"
echo "  SUMMARY"
echo "============================================================"

python3 - "$FOSSA_RESULTS" "$SEMGREP_RESULTS" <<'PYEOF'
import sys, json, subprocess

fossa_file   = sys.argv[1]
semgrep_file = sys.argv[2]

COPYLEFT = {"lgpl", "gpl", "agpl", "copyleft", "gnu", "mpl"}

print("\n── LICENCE SCAN ─────────────────────────────────────────")
try:
    with open(fossa_file) as f:
        data = json.load(f)

    # Build a licence lookup from pip-licenses (has actual licence text)
    pip_lic = {}
    try:
        import sys as _sys
        raw = subprocess.check_output(
            [_sys.executable, "-m", "piplicenses", "--format=json", "--with-urls"],
            text=True, stderr=subprocess.DEVNULL
        )
        for p in json.loads(raw):
            pip_lic[p["Name"].lower()] = p.get("License", "Unknown")
    except Exception:
        pass

    deps = []
    if isinstance(data, list):
        for d in data:
            deps.append({
                "name":    d.get("Name", d.get("name", "?")),
                "version": d.get("Version", d.get("version", "?")),
                "license": d.get("License", d.get("license", "Unknown")),
            })
    elif isinstance(data, dict) and "projects" in data:
        # FOSSA --output format
        for proj in data["projects"]:
            for dep in proj.get("graph", {}).get("deps", []):
                ver_obj = dep.get("version", {})
                ver = ver_obj.get("value", "?") if isinstance(ver_obj, dict) else str(ver_obj)
                name = dep.get("name", "?")
                lic = pip_lic.get(name.lower(), "Unknown")
                deps.append({"name": name, "version": ver, "license": lic})
    elif isinstance(data, dict):
        for dep in data.get("directDependencies", []) + data.get("transitiveDependencies", []):
            deps.append({
                "name":    dep.get("name", "?"),
                "version": dep.get("version", "?"),
                "license": dep.get("license", {}).get("name", "Unknown") if isinstance(dep.get("license"), dict) else str(dep.get("license","Unknown")),
            })

    print(f"  Dependencies found: {len(deps)}")
    licence_counts = {}
    copyleft_found = []
    for d in deps:
        lic = d["license"]
        licence_counts[lic] = licence_counts.get(lic, 0) + 1
        if any(kw in lic.lower() for kw in COPYLEFT):
            copyleft_found.append(d)

    print("\n  Licence breakdown:")
    for lic, cnt in sorted(licence_counts.items()):
        print(f"    {lic:40s}  {cnt} dep(s)")

    if copyleft_found:
        print(f"\n  [!] COPYLEFT / LGPL LICENCES FLAGGED ({len(copyleft_found)}):")
        for d in copyleft_found:
            print(f"    ⚠  {d['name']} {d['version']}  →  {d['license']}")
    else:
        print("\n  No copyleft licences detected in this scan pass.")

except Exception as e:
    print(f"  Could not parse licence results: {e}")

print("\n── SEMGREP FINDINGS ──────────────────────────────────────")
try:
    with open(semgrep_file) as f:
        sg = json.load(f)

    findings = sg.get("results", [])
    by_sev = {}
    for r in findings:
        sev = r.get("extra", {}).get("severity", r.get("severity", "UNKNOWN")).upper()
        by_sev.setdefault(sev, []).append(r)

    print(f"  Total findings: {len(findings)}")
    for sev in ("ERROR", "WARNING", "INFO", "UNKNOWN"):
        if sev in by_sev:
            print(f"    {sev}: {len(by_sev[sev])}")

    print()
    for sev in ("ERROR", "WARNING", "INFO", "UNKNOWN"):
        if sev not in by_sev:
            continue
        print(f"  [{sev}]")
        for r in by_sev[sev]:
            path  = r.get("path", "?")
            line  = r.get("start", {}).get("line", "?")
            rule  = r.get("check_id", r.get("rule_id", "?"))
            msg   = r.get("extra", {}).get("message", r.get("message", "?"))[:120]
            print(f"    {path}:{line}  [{rule}]")
            print(f"      {msg}")
        print()

except Exception as e:
    print(f"  Could not parse Semgrep results: {e}")

print("============================================================")
PYEOF

echo ""
echo "Done. Full results in:"
echo "  $FOSSA_RESULTS"
echo "  $SEMGREP_RESULTS"
