# OSS Scan Demo

A self-contained demo project showing how to combine **Semgrep** (static security analysis) and **FOSSA** (open source licence compliance) in a GitHub Actions CI/CD pipeline.

Both tools are configured to find real issues — the source code contains deliberate vulnerabilities and the dependencies include copyleft-licenced packages.

---

## Running the scan manually

### In GitHub Actions (no local setup needed)

1. Go to the **Actions** tab
2. Click **Security & Licence Scan** in the left sidebar
3. Click **Run workflow** → **Run workflow**

The full report prints in the workflow log. Scan result JSON files are saved as downloadable artifacts on each run.

### Locally (macOS)

```bash
# One-time setup
python3 -m venv venv
source venv/bin/activate
pip install semgrep pip-licenses
pip install -r requirements.txt

# Download FOSSA CLI (arm64 Mac)
curl -sL https://raw.githubusercontent.com/fossas/fossa-cli/master/install-latest.sh | bash
sudo mv fossa /usr/local/bin/fossa   # or leave it in the project dir

# Run everything
bash run_scans.sh

# Parse and print combined report
python3 parse_results.py
```

---

## What gets scanned

| Tool | Scans | Output |
|---|---|---|
| **Semgrep** | `app.py` source code — taint analysis and pattern matching | `semgrep-results.json` |
| **FOSSA** | Full transitive dependency graph from `requirements.txt` | `fossa-results.json` |
| **pip-licenses** | Licence metadata for installed packages (enriches FOSSA output) | merged into report |

---

## Deliberate vulnerabilities in app.py

The source file contains five intentional security issues for the tools to find:

| Issue | Line | Rule triggered |
|---|---|---|
| Hardcoded API key and secret | 27–28 | `hardcoded-api-key-or-secret` (custom rule) |
| SQL injection via string concatenation | 46 | `tainted-sql-string` |
| `eval()` on user input (RCE) | 61 | `eval-injection` |
| `subprocess` with `shell=True` (command injection) | 73–75 | `subprocess-injection`, `subprocess-shell-true` |
| Debug route exposing `os.environ` | 85 | flagged via `debug-enabled` + `host=0.0.0.0` |

Semgrep also finds a sixth unplanted issue — **SSRF** on lines 100–102 where a user-supplied URL is passed directly to `requests.get()`.

---

## Deliberate licence flags in requirements.txt

| Package | Licence | Why flagged |
|---|---|---|
| `chardet` | GNU LGPLv2+ | Copyleft — binary distribution may require relinking rights |
| `pynput` | GNU LGPLv3 | Copyleft — adds patent and DRM restrictions vs v2 |
| `certifi` | Mozilla Public License 2.0 | Weak copyleft — only modified certifi files must stay MPL |

---

## CI/CD behaviour

The workflow runs on every push and every pull request. The **"Fail on ERROR findings"** step exits with code 1 if Semgrep finds any ERROR-severity issues — this is intentional and demonstrates how to gate a PR merge on scan results.

To use this pattern in a production repo, set the failing step to only run on pull requests and configure branch protection rules to require the check to pass before merging.

Semgrep findings are also uploaded to the **Security → Code scanning** tab as SARIF, where they appear as inline annotations on pull requests.

---

## Project structure

```
.
├── .github/
│   └── workflows/
│       └── scan.yml          # GitHub Actions workflow
├── .semgrep.yml              # Custom Semgrep rule (hardcoded credentials)
├── app.py                    # Flask app with deliberate vulnerabilities
├── fossa.yml                 # FOSSA project config
├── parse_results.py          # Combined compliance report generator
├── requirements.txt          # Mixed-licence dependencies
├── run_scans.sh              # Local scan orchestration script
├── fossa-results.json        # FOSSA output (committed for reference)
├── semgrep-results.json      # Semgrep output (committed for reference)
└── OSS_SCAN_GUIDE.md         # Full documentation
```

---

## Further reading

Full documentation including how each tool works, CI/CD integration examples for GitHub Actions / GitLab CI / Azure DevOps, C# support, and pros/cons: see [OSS_SCAN_GUIDE.md](OSS_SCAN_GUIDE.md).
