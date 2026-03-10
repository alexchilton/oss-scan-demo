#!/usr/bin/env python3
"""
parse_results.py
Combined compliance report: FOSSA licence data + Semgrep security findings.
"""

import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
FOSSA_FILE  = SCRIPT_DIR / "fossa-results.json"
SEMGREP_FILE = SCRIPT_DIR / "semgrep-results.json"

COPYLEFT_KEYWORDS = {"lgpl", "gpl", "agpl", "copyleft", "gnu lesser", "mozilla public"}

# Why findings matter for AI-generated code review (one-liners per rule pattern)
AI_CONTEXT = {
    "eval":            "AI code generators commonly suggest eval() for dynamic expression parsing without flagging the RCE risk.",
    "sql":             "LLMs frequently produce string-interpolated SQL when asked to 'query by user input', missing parameterisation.",
    "shell":           "AI tools often suggest shell=True subprocess calls for convenience, hiding command-injection vectors.",
    "hardcoded":       "AI completions routinely inline placeholder secrets that developers forget to replace before committing.",
    "secret":          "Hardcoded credential patterns are one of the top classes of AI-assisted code introducing supply-chain risk.",
    "environ":         "AI-generated debug routes often dump os.environ wholesale — safe in local context, catastrophic in prod.",
    "debug":           "LLMs default to debug=True for Flask/Django because training data is full of tutorial code that does this.",
    "api_key":         "Variable names like api_key with string literals are a top-5 finding in AI-generated code across all languages.",
    "subprocess":      "AI tools suggest subprocess with shell=True ~40% of the time for shell-like tasks, per public research.",
    "inject":          "Injection flaws (SQL, shell, template) are consistently the #1 OWASP category found in AI-generated code.",
    "default":         "AI-generated code often introduces security issues by copying patterns from insecure training examples.",
}


def ai_context_for(rule_id: str, message: str) -> str:
    combined = (rule_id + " " + message).lower()
    for kw, ctx in AI_CONTEXT.items():
        if kw in combined:
            return ctx
    return AI_CONTEXT["default"]


def load_json(path: Path) -> dict | list | None:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"  [!] File not found: {path}", file=sys.stderr)
        return None
    except json.JSONDecodeError as e:
        print(f"  [!] JSON parse error in {path}: {e}", file=sys.stderr)
        return None


def parse_licence_data(data) -> list[dict]:
    """Normalise pip-licenses or FOSSA JSON into a flat list of dicts."""
    deps = []
    if isinstance(data, list):
        # pip-licenses format
        for d in data:
            deps.append({
                "name":    d.get("Name", d.get("name", "unknown")),
                "version": d.get("Version", d.get("version", "?")),
                "license": d.get("License", d.get("license", "Unknown")),
                "url":     d.get("URL", d.get("url", "")),
            })
    elif isinstance(data, dict):
        # FOSSA --output format: {"projects": [{"graph": {"deps": [...]}}]}
        if "projects" in data:
            for proj in data["projects"]:
                graph = proj.get("graph", {})
                for dep in graph.get("deps", []):
                    ver_obj = dep.get("version", {})
                    version = ver_obj.get("value", "?") if isinstance(ver_obj, dict) else str(ver_obj)
                    # Use enriched licence name if available
                    lic = dep.get("_license_name", "Unknown")
                    deps.append({
                        "name":    dep.get("name", "?"),
                        "version": version,
                        "license": lic,
                        "url":     "",
                    })
        else:
            # Older FOSSA / other dict format
            for section in ("directDependencies", "transitiveDependencies", "dependencies"):
                for dep in data.get(section, []):
                    lic_field = dep.get("license", {})
                    lic_name = (
                        lic_field.get("name", "Unknown")
                        if isinstance(lic_field, dict)
                        else str(lic_field)
                    )
                    deps.append({
                        "name":    dep.get("name", "?"),
                        "version": dep.get("version", "?"),
                        "license": lic_name,
                        "url":     dep.get("homepage", ""),
                    })
    return deps


def is_copyleft(license_name: str) -> bool:
    low = license_name.lower()
    return any(kw in low for kw in COPYLEFT_KEYWORDS)


def section1_licences(data):
    print("=" * 70)
    print("SECTION 1 - LICENCE COMPLIANCE (FOSSA / pip-licenses)")
    print("=" * 70)

    if data is None:
        print("  No licence data available.")
        print()
        return

    deps = parse_licence_data(data)

    if not deps:
        print("  No dependencies parsed from licence scan output.")
        print()
        return

    print(f"\n  {'Package':<30} {'Version':<12} {'Licence'}")
    print(f"  {'-'*30} {'-'*12} {'-'*30}")

    copyleft_list = []
    for d in sorted(deps, key=lambda x: x["name"].lower()):
        flag = ""
        if is_copyleft(d["license"]):
            flag = "  ← [COPYLEFT WARNING]"
            copyleft_list.append(d)
        print(f"  {d['name']:<30} {d['version']:<12} {d['license']}{flag}")

    print()
    if copyleft_list:
        print(f"  ⚠  COPYLEFT / LGPL PACKAGES REQUIRING REVIEW ({len(copyleft_list)}):")
        for d in copyleft_list:
            print(f"     • {d['name']} {d['version']} — {d['license']}")
            print(f"       Distribution of this software may require source disclosure.")
    else:
        print("  ✓  No copyleft licences detected.")
    print()


def section2_semgrep(data):
    print("=" * 70)
    print("SECTION 2 - SECURITY FINDINGS (SEMGREP)")
    print("=" * 70)

    if data is None:
        print("  No Semgrep data available.")
        print()
        return

    findings = data.get("results", [])
    errors   = data.get("errors", [])

    if errors:
        print(f"\n  Semgrep reported {len(errors)} scan error(s):")
        for e in errors[:3]:
            print(f"    • {e.get('message', str(e))[:100]}")

    if not findings:
        print("\n  No Semgrep findings.")
        print()
        return

    # Group by severity
    by_sev: dict[str, list] = {}
    for r in findings:
        sev = r.get("extra", {}).get("severity", r.get("severity", "UNKNOWN")).upper()
        by_sev.setdefault(sev, []).append(r)

    print(f"\n  Total findings: {len(findings)}")
    for sev in ("ERROR", "WARNING", "INFO", "UNKNOWN"):
        if sev in by_sev:
            print(f"    {sev}: {len(by_sev[sev])}")

    for sev in ("ERROR", "WARNING", "INFO", "UNKNOWN"):
        if sev not in by_sev:
            continue

        print(f"\n  ── {sev} ──────────────────────────────────────────────────")
        for i, r in enumerate(by_sev[sev], 1):
            path    = r.get("path", "?")
            start   = r.get("start", {})
            line    = start.get("line", "?")
            rule_id = r.get("check_id", r.get("rule_id", "?"))
            extra   = r.get("extra", {})
            message = extra.get("message", r.get("message", "?"))
            # Trim rule_id prefix for readability
            short_rule = rule_id.split(".")[-1] if "." in rule_id else rule_id

            ai_note = ai_context_for(rule_id, message)

            print(f"\n  [{i}] {short_rule}")
            print(f"      File   : {path}, line {line}")
            print(f"      Rule   : {rule_id}")
            print(f"      Message: {message[:200]}")
            print(f"      AI note: {ai_note}")

    print()


def load_piplicenses() -> dict:
    """Try to get real licence names from pip-licenses."""
    try:
        import subprocess, json as _json, sys as _sys
        out = subprocess.check_output(
            [_sys.executable, "-m", "piplicenses", "--format=json", "--with-urls"],
            text=True, stderr=subprocess.DEVNULL
        )
        return {p["Name"].lower(): p.get("License", "Unknown") for p in _json.loads(out)}
    except Exception:
        return {}


def main():
    print()
    print("  OSS COMPLIANCE REPORT")
    print(f"  Generated from: {FOSSA_FILE.name} + {SEMGREP_FILE.name}")
    print()

    fossa_data   = load_json(FOSSA_FILE)
    semgrep_data = load_json(SEMGREP_FILE)

    # Enrich FOSSA graph deps with actual licence names from pip-licenses
    if isinstance(fossa_data, dict) and "projects" in fossa_data:
        pip_lic = load_piplicenses()
        if pip_lic:
            for proj in fossa_data.get("projects", []):
                for dep in proj.get("graph", {}).get("deps", []):
                    name = dep.get("name", "").lower()
                    if name in pip_lic:
                        dep["_license_name"] = pip_lic[name]

    section1_licences(fossa_data)
    section2_semgrep(semgrep_data)

    print("=" * 70)
    print("END OF REPORT")
    print("=" * 70)
    print()


if __name__ == "__main__":
    main()
