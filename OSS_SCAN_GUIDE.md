# OSS Security & Licence Compliance Scanning
## Semgrep + FOSSA — What We Did, How It Works, and CI/CD Integration

---

## Table of Contents

1. [What We Built](#what-we-built)
2. [Tool Overview](#tool-overview)
3. [How Each Tool Works](#how-each-tool-works)
4. [Project Structure](#project-structure)
5. [The Deliberate Vulnerabilities](#the-deliberate-vulnerabilities)
6. [Scan Results](#scan-results)
7. [CI/CD Integration](#cicd-integration)
8. [C# / .NET Support](#c--net-support)
9. [Pros and Cons](#pros-and-cons)
10. [When to Use What](#when-to-use-what)

---

## What We Built

A self-contained test project that demonstrates two complementary scanning tools working together:

- **Semgrep** — static analysis of your source code, finding security vulnerabilities by pattern matching and taint analysis
- **FOSSA** — dependency graph analysis, identifying every third-party package and its licence obligations

We deliberately wrote a Flask application (`app.py`) containing five classic security vulnerabilities and a `requirements.txt` with packages spanning multiple licence types including LGPL. Both tools found real issues — nothing was simulated.

The output is a combined compliance report covering both security posture and licence risk, suitable for engineering review or audit evidence.

---

## Tool Overview

### Semgrep

| Property | Detail |
|---|---|
| What it scans | Your source code |
| How it works | AST pattern matching + taint analysis |
| Languages | 30+ including Python, C#, Java, Go, JS/TS, Ruby |
| Rule source | Community rules (`p/python`, `p/owasp-top-ten`, `p/secrets`), custom YAML rules |
| Output formats | JSON, SARIF, text |
| Licence | OSS (Community) / Commercial (Pro with more rules) |
| Account required | No for community rulesets |

### FOSSA

| Property | Detail |
|---|---|
| What it scans | Your dependency graph (not your source code) |
| How it works | Reads package manifests, resolves transitive deps, looks up licence metadata |
| Ecosystems | pip, NuGet, npm, Maven, Go modules, Cargo, and more |
| Output formats | JSON, SARIF, policy reports |
| Licence | Commercial (free tier available) |
| Account required | For upload/policy enforcement — `--output` mode works offline with no account |

They complement each other cleanly: Semgrep tells you what *your code* is doing wrong; FOSSA tells you what *your dependencies* are licensed under. A complete security posture requires both.

---

## How Each Tool Works

### Semgrep — Static Analysis

Semgrep parses source code into an **Abstract Syntax Tree (AST)** — a structured representation of what the code does rather than what it looks like. Rules are written in YAML and describe patterns against that tree.

There are two levels of analysis:

**Pattern matching** — finds dangerous constructs regardless of context:
```yaml
# This rule fires whenever eval() appears with any argument
pattern: eval(...)
```

**Taint analysis** — tracks data from an untrusted *source* (e.g. `request.args.get()`) through the code to a dangerous *sink* (e.g. `subprocess.run()`, `eval()`, SQL string), even across function calls and assignments. This is what caught the SQL injection and command injection in `app.py` — Semgrep followed the data flow from the HTTP request parameter through to the dangerous operation.

Custom rules (our `.semgrep.yml`) can be added on top of the community rulesets to enforce project-specific policies.

### FOSSA — Dependency Analysis

FOSSA reads your package manifest (`requirements.txt`, `packages.lock.json`, `pom.xml`, etc.), resolves the full transitive dependency tree (every package your packages depend on), and looks up licence metadata for each one.

In `--output` mode (no API key required), it writes a JSON graph of the full dependency tree. We combined this with **pip-licenses** running inside the venv to attach actual licence names to each package, since `--output` mode does not embed licence text directly.

The licence data comes from the metadata each package publisher includes — FOSSA does not make legal determinations, it surfaces the declared licences and flags known copyleft identifiers for human review.

---

## Project Structure

```
oss-scan-test/
├── app.py                  # Flask app with deliberate vulnerabilities
├── requirements.txt        # Mixed-licence dependencies
├── fossa.yml               # FOSSA project config
├── .semgrep.yml            # Custom Semgrep rules
├── run_scans.sh            # Orchestration script
├── parse_results.py        # Combined compliance report generator
├── fossa-results.json      # FOSSA output (generated)
├── semgrep-results.json    # Semgrep output (generated)
└── fossa                   # FOSSA CLI binary (arm64 macOS)
```

### fossa.yml

```yaml
version: 3
project:
  id: "custom+1/oss-scan-test"
  name: "oss-scan-test"
targets:
  only:
    - type: pip
      path: .
```

Tells FOSSA to analyse the pip dependency graph rooted at the current directory. In a real project you might add multiple targets for mixed ecosystems (e.g. Python backend + npm frontend).

### .semgrep.yml (custom rule)

```yaml
rules:
  - id: hardcoded-api-key-or-secret
    patterns:
      - pattern-either:
          - pattern: api_key = "..."
          - pattern: secret = "..."
    message: Hardcoded credential detected...
    languages: [python]
    severity: ERROR
```

This rule fires any time a variable named `api_key` or `secret` is assigned a string literal — a simple but effective guard against the most common AI-assisted coding mistake.

---

## The Deliberate Vulnerabilities

`app.py` contains five intentional security issues, each representing a common failure pattern in real and AI-generated code:

### (a) Hardcoded secrets — lines 27–28

```python
api_key = "sk-prod-abc123XYZsecretDONOTSHARE9999"
secret = "super_secret_password_hardcoded_in_source"
```

**Risk:** Anyone with read access to the repo — including CI runners, contractors, ex-employees — can extract these credentials. They persist in `git log` even after deletion. The correct pattern is `os.environ.get("API_KEY")` backed by a secrets manager (Vault, AWS Secrets Manager, GitHub Actions secrets).

**Caught by:** Custom `.semgrep.yml` rule — both lines flagged as ERROR.

### (b) SQL injection — line 46

```python
query = "SELECT * FROM users WHERE username = '" + username + "'"
conn.execute(query)
```

**Risk:** An attacker passes `' OR '1'='1' --` as the username, which dumps the entire users table. With a writable database they can also `DROP TABLE` or insert data. Fix: use parameterised queries: `conn.execute("SELECT * FROM users WHERE username = ?", (username,))`.

**Caught by:** `python.flask.security.injection.tainted-sql-string` — Semgrep tracked `request.args.get("username")` through the string concatenation to `conn.execute()`.

### (c) eval() on user input — line 61

```python
result = eval(expression)  # expression from request.args
```

**Risk:** Remote Code Execution. An attacker passes `?expr=__import__('os').system('id')` and executes arbitrary commands on the server. `eval()` in Python has no sandbox. Fix: use `ast.literal_eval()` for safe value parsing, or a dedicated expression library.

**Caught by:** `eval-injection` (ERROR) and `user-eval` (WARNING) — two separate rules from different rule packs both flagged this.

### (d) subprocess with shell=True — lines 73–75

```python
output = subprocess.run(
    f"ping -c 1 {host}",
    shell=True, ...
)
```

**Risk:** Command injection. `?host=localhost; cat /etc/passwd` causes the shell to run both `ping` and `cat`. With `shell=True`, the string is passed directly to `/bin/sh`. Fix: `shell=False`, pass arguments as a list: `["ping", "-c", "1", host]`.

**Caught by:** Three separate rules — `subprocess-injection`, `dangerous-subprocess-use`, `subprocess-shell-true` — each catching a different aspect of the problem.

### (e) Debug route exposing environment variables — line 85

```python
@app.route("/debug/env")
def debug_env():
    return jsonify(dict(os.environ))
```

**Risk:** `os.environ` in a production service typically contains database passwords, API keys, JWT signing secrets, and cloud provider credentials. Any authenticated (or unauthenticated) caller gets all of them. This pattern is extremely common in AI-generated debug scaffolding.

**Caught by:** Not directly flagged by Semgrep in this run (no community rule for env-dump routes currently), but `debug=True` and `host=0.0.0.0` on line 108 were flagged as WARNING — the combination makes this route publicly reachable.

**Bonus finding — SSRF — lines 100–102**

```python
url = request.args.get("url", "https://example.com")
resp = requests.get(url, timeout=5)
```

This wasn't one of the five deliberate issues but Semgrep caught it anyway. An attacker passes `?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/` to exfiltrate AWS IAM credentials via the EC2 metadata endpoint. Semgrep flagged it twice (Django and Flask taint rules both matched).

---

## Scan Results

### FOSSA — 38 dependencies, 3 copyleft flags

FOSSA resolved the full transitive dependency tree from 9 direct packages in `requirements.txt` to 38 total packages (celery alone pulls in amqp, billiard, kombu, vine, etc.).

**Copyleft packages flagged:**

| Package | Licence | Obligation |
|---|---|---|
| `chardet` | GNU LGPLv2+ | If you distribute a binary, you must allow end users to relink against a modified chardet |
| `pynput` | GNU LGPLv3 | Same relinking obligation plus LGPLv3 adds patent and DRM restrictions absent in v2 |
| `certifi` | Mozilla Public License 2.0 | Weak copyleft — only modified certifi files must stay MPL; your app code is unaffected |

For a proprietary commercial product, `chardet` and `pynput` would typically require a legal review. For an internal tool or open source project, LGPL is usually fine.

**Licence distribution across all 38 packages:**

| Licence | Count |
|---|---|
| BSD License | 10 |
| MIT / MIT License | 14 |
| Apache Software License | 5 |
| GNU LGPLv2+ / LGPLv3 | 2 |
| MPL 2.0 | 1 |
| Other | 6 |

### Semgrep — 12 findings

| Severity | Count |
|---|---|
| ERROR | 9 |
| WARNING | 3 |

Every deliberate vulnerability was caught. The SSRF finding was a bonus — Semgrep found a sixth issue we didn't plant.

---

## CI/CD Integration

### GitHub Actions — Full Example

```yaml
name: Security & Compliance Scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  semgrep:
    name: Semgrep SAST
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep
    steps:
      - uses: actions/checkout@v4

      - name: Run Semgrep
        run: |
          semgrep scan \
            --config p/python \
            --config p/owasp-top-ten \
            --config p/secrets \
            --config .semgrep.yml \
            --sarif \
            --output semgrep.sarif \
            src/
        # Exits 1 if findings exist — blocks the PR

      - name: Upload SARIF to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: semgrep.sarif

  fossa:
    name: FOSSA Licence Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run FOSSA
        uses: fossas/fossa-action@main
        with:
          api-key: ${{ secrets.FOSSA_API_KEY }}
          # Remove api-key and add --output flag for offline mode
```

### GitLab CI — Full Example

```yaml
stages:
  - security

semgrep:
  stage: security
  image: semgrep/semgrep
  script:
    - semgrep scan
        --config p/python
        --config p/owasp-top-ten
        --config p/secrets
        --config .semgrep.yml
        --json
        --output semgrep-results.json
        src/
  artifacts:
    reports:
      sast: semgrep-results.json
    paths:
      - semgrep-results.json
  allow_failure: false   # blocks merge on any finding

fossa:
  stage: security
  script:
    - curl -H 'Cache-Control: no-cache'
        https://raw.githubusercontent.com/fossas/fossa-cli/master/install-latest.sh | bash
    - fossa analyze
    - fossa test   # fails if policy violations detected
  only:
    - main
```

### Azure DevOps — Full Example

```yaml
trigger:
  - main
  - feature/*

pool:
  vmImage: ubuntu-latest

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.11'

  - script: pip install semgrep
    displayName: Install Semgrep

  - script: |
      semgrep scan \
        --config p/python \
        --config p/owasp-top-ten \
        --config p/secrets \
        --sarif --output $(Build.ArtifactStagingDirectory)/semgrep.sarif \
        src/
    displayName: Run Semgrep
    continueOnError: false   # fail the build on findings

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: $(Build.ArtifactStagingDirectory)
      artifactName: security-reports
```

### Recommended Pipeline Strategy

```
PR opened
    │
    ├── Semgrep (every PR)
    │       ERROR findings → block merge
    │       WARNING findings → post comment, do not block
    │       INFO findings → log only
    │
    └── FOSSA (every PR, or on schedule)
            New copyleft dependency → notify, do not block
            GPL/AGPL in commercial product → block merge
            Policy violation configured in FOSSA dashboard → block

Merge to main
    │
    └── Both scans + full report artifact saved

Release tag
    │
    └── FOSSA licence report generated as audit artefact
```

### Severity Threshold Configuration

Semgrep lets you set a minimum severity to fail the build:

```bash
semgrep scan ... --severity ERROR   # only fail on ERROR
semgrep scan ... --severity WARNING # fail on WARNING and above
```

For a new project onboarding these tools, start with `--severity ERROR` only, fix those, then tighten to `--severity WARNING`. Going straight to WARNING on a mature codebase will produce hundreds of findings and cause developers to ignore the tool.

---

## C# / .NET Support

Both tools work with C# with minimal configuration changes.

### Semgrep for C#

```bash
semgrep scan \
  --config p/csharp \
  --config p/owasp-top-ten \
  --config p/secrets \
  --config .semgrep.yml \
  src/
```

Key C# rules that fire on common patterns:

| Vulnerability | Rule | C# equivalent of our app.py issues |
|---|---|---|
| SQL injection | `csharp.lang.security.sqli` | `string.Format("SELECT ... {0}", input)` or string interpolation in SQL |
| Command injection | `csharp.lang.security.process` | `Process.Start()` with user-controlled arguments |
| Hardcoded secrets | `p/secrets` | `string apiKey = "sk-..."` |
| Insecure deserialisation | `csharp.lang.security.deserialisation` | `BinaryFormatter.Deserialize()` — a top .NET vulnerability |
| XXE | `csharp.lang.security.xxe` | `XmlReader` without safe settings |
| SSRF | `csharp.lang.security.ssrf` | `HttpClient.GetAsync(userInput)` |

### FOSSA for C#

Point FOSSA at a `.csproj`, `.sln`, or `packages.lock.json`. It reads NuGet package references and resolves the full dependency tree including transitive packages. Licence detection works the same way.

```yaml
# fossa.yml for a .NET project
version: 3
project:
  name: my-dotnet-app
targets:
  only:
    - type: nuget
      path: MyApp/MyApp.csproj
```

---

## Pros and Cons

### Semgrep

| Pros | Cons |
|---|---|
| Fast — typical codebase scans in under 30 seconds | Community rules have false positives; needs tuning |
| No code leaves your machine (runs locally/in CI) | Taint analysis can miss multi-file flows in Community edition |
| Custom rules are easy to write in YAML | Pro features (cross-file analysis, secrets with validity checks) require paid tier |
| SARIF output integrates natively with GitHub, GitLab, Azure DevOps | C# rule coverage is thinner than Python/JS |
| Catches issues code review and linting miss | Cannot find logic bugs, only known-bad patterns |
| Works on code that doesn't compile | |
| Free for open source and individual use | |

### FOSSA

| Pros | Cons |
|---|---|
| Full transitive dependency resolution (not just direct deps) | Full policy enforcement requires a paid account |
| Detects licence obligations developers are unaware of | `--output` mode doesn't embed licence text — needs pip-licenses or similar to enrich |
| Supports 20+ ecosystems from one tool | Slower than a simple `pip-licenses` run for basic licence listing |
| Policy-as-code: define which licences are allowed/blocked | FOSSA's legal interpretations are not legal advice |
| Audit trail and report generation for compliance | Can produce noise on packages with ambiguous or multi-licence declarations |
| GitHub/GitLab/Jira integrations in paid tier | |

### Combined Approach

| Pros | Cons |
|---|---|
| Covers both code quality and supply chain risk | Two tools to maintain and keep updated |
| Complementary — neither tool does what the other does | Requires policy decisions on what severity/licence types to block |
| Both produce machine-readable output (JSON/SARIF) for downstream tooling | Initial tuning needed to reduce false positives to acceptable levels |
| Neither requires sending code to a third-party API | |

### Compared to Alternatives

| Tool | What it does | vs Semgrep+FOSSA |
|---|---|---|
| **Snyk** | Combined SAST + SCA in one tool | Easier setup, worse custom rule support, more expensive at scale |
| **Dependabot** | Dependency vulnerability (CVE) scanning | Finds CVEs in deps, not licence issues; no source code scanning |
| **SonarQube** | Broad code quality + security | Deeper code quality rules, weaker on supply chain, heavier infrastructure |
| **Bandit** (Python only) | Python security linting | Simpler than Semgrep, no taint analysis, Python only |
| **pip-licenses alone** | Licence listing | No FOSSA graph resolution, no policy enforcement, no CI integration |
| **GitHub Advanced Security** | SAST + secret scanning | Good integration if on GitHub Enterprise; runs CodeQL not Semgrep rules |

### What These Tools Cannot Do

It is important to be clear about the limits:

- **They cannot find logic bugs** — a business logic flaw that bypasses authorisation is invisible to pattern matching
- **They cannot evaluate runtime behaviour** — a race condition or timing attack won't appear in a static scan
- **They cannot replace a penetration test** — they find known-bad patterns, not novel attack chains
- **FOSSA does not provide legal advice** — a flagged LGPL licence still requires a lawyer to interpret the actual obligation in your specific distribution context
- **Semgrep community rules will miss things** — coverage is not exhaustive; a `eval()` hidden behind two function calls may not be traced

They are a first filter, not a guarantee. The correct mental model is: these tools catch the obvious things automatically so that human review time is spent on the non-obvious things.

---

## When to Use What

| Scenario | Recommended |
|---|---|
| Every PR on a production service | Semgrep (`--severity ERROR`) blocking, FOSSA notifying |
| Open source project | Semgrep free tier + pip-licenses in CI |
| Commercial product with redistribution | FOSSA paid (policy enforcement on GPL/AGPL) |
| Regulated environment (SOC2, ISO27001) | Both tools, save SARIF output as audit artefacts per release |
| Quick one-off check on a new dependency | `pip-licenses` or `fossa analyze --output` locally |
| AI-assisted development team | Semgrep with custom rules targeting AI coding patterns (eval, shell=True, hardcoded secrets) — the tools catch what code review misses when moving fast |
