# AppScan 360° DAST GitHub Action

Run authenticated DAST scans against your application on a self-managed **HCL AppScan 360°** instance, directly from GitHub Actions — with scan status tracking, results and security gates in the workflow run, rescans, a scan-history browser, and a post-scan hook for custom scripts.

A GitHub Action for automated DAST scanning with HCL AppScan 360°, licensed under Apache-2.0. See [CHANGELOG.md](CHANGELOG.md) for the change history.

```yaml
- uses: alexhcl/appscan360-dast-action@main
  env:
    ACCEPTSSL: "true"           # TLS skipped by default; set "false" to enforce verification
  with:
    baseurl:        ${{ vars.APPSCAN_URL }}
    asoc_key:       ${{ secrets.APPSCAN_KEY }}
    asoc_secret:    ${{ secrets.APPSCAN_SECRET }}
    application_id: ${{ vars.APPSCAN_APP_ID }}
```

---

## Requirements

A quick checklist — details for each follow below.

| Need | Summary |
|---|---|
| **Runner** | Self-hosted, **Linux or Windows**, able to reach the AppScan 360° server and the scan target. |
| **PowerShell 7+** | `pwsh` on the runner's PATH. (Windows PowerShell 5.1 alone is not enough.) |
| **TLS trust** | The runner must trust the server's certificate (installed per runner). |
| **Credentials** | AppScan API key ID + secret (as GitHub secrets) and the application GUID. |
| **Docker** | Only for `ephemeral_presence: true`, and only on Linux runners. |

### Runner

Use a **self-hosted** runner — the action needs network access to your AppScan 360° server and to the scan target, which GitHub-hosted runners usually can't reach. It runs on **Linux or Windows**; target a specific OS with labels:

```yaml
runs-on: [self-hosted, linux]     # or: [self-hosted, windows]
```

### PowerShell 7+

The action runs its scripts with **PowerShell 7** (`pwsh`), so `pwsh` must be on the PATH of the account the runner uses. Windows PowerShell 5.1 is **not recommended** — the action launches `pwsh` directly and relies on 7-only features.

> If `pwsh` is missing, the job fails immediately with `spawn pwsh ENOENT`.

**Install on Ubuntu** (via the Microsoft apt repo — preferred over snap, since apt puts `pwsh` in `/usr/bin`, which the runner service always sees):

```bash
sudo apt-get update && sudo apt-get install -y wget apt-transport-https software-properties-common
source /etc/os-release
wget -q "https://packages.microsoft.com/config/ubuntu/${VERSION_ID}/packages-microsoft-prod.deb"
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update && sudo apt-get install -y powershell
pwsh -v                           # expect 7.x — then restart the runner service
```

**Install on Windows** (as Administrator):

```powershell
winget install Microsoft.PowerShell
pwsh -v                           # expect 7.x — then restart the runner so it picks up the new PATH
```

### TLS trust

`pwsh` validates the server certificate against **that OS's system trust store**, so the CA must be installed on **each runner**.

**Linux:**
```bash
sudo cp appscan-ca.crt /usr/local/share/ca-certificates/appscan-ca.crt
sudo update-ca-certificates
```

**Windows** (Administrator — the machine store, so the runner service can see it):
```powershell
certutil -addstore -f Root appscan-ca.crt
# verify: an HTTP 400 "KeyId field is required" means TLS is fine (a cert error would show instead)
pwsh -c "Invoke-RestMethod https://<your-server>/api/v4/Account/ApiKeyLogin -Method POST -Body '{}' -ContentType 'application/json'"
```

> **TLS default:** the action **skips certificate verification by default** (`ACCEPTSSL` defaults to `"true"`), because self-managed AppScan 360 servers often present a certificate whose CA isn't in the runner's trust store. This is convenient but insecure — it accepts any certificate and exposes the API key to interception. **For production, trust the server CA on the runner and set `ACCEPTSSL: "false"` on the step** (it's an `env:` value, **not** an input) to enforce strict TLS.

### Credentials

Create an API key (ID + secret) in the AppScan 360° portal and store both as **GitHub secrets**. You also need the **application GUID** (from the app's page in the portal).

### Docker

Only needed when `ephemeral_presence: true` deploys a temporary Presence on the runner — and that works on **Linux runners only** (the Presence image is a Linux container).

## Operating modes

| Mode | How | What happens |
|---|---|---|
| **New scan** (default) | `rescan_latest` absent/false | Creates a fresh scan from the creation inputs (target + login, or an uploaded `.scan`/`.scant` file). A provided `scan_id` is ignored with a warning. |
| **Rescan — auto** | `rescan_latest: true` | New execution of the application's **most recent DAST scan** (auto-resolved from the server; SAST/SCA scans are skipped). First run with no scan yet → falls back to creating one, so the workflow bootstraps itself. |
| **Rescan — explicit** | `rescan_latest: true` + `scan_id` | New execution of exactly that scan. |
| **Monitor** | `monitor: true` | No scan runs: lists past scans (filtered) in the job summary with portal links and downloads their HTML reports. |

In every rescan the scan's **server-side configuration wins**: `starting_URL`, `login_*`, `scan_or_scant_file` and `dynamic_scan_type` are not sent, and the job summary shows the target as _(from the scan's stored configuration)_. `scan_name` **is** honored on rescans: the action renames the scan (best-effort `PUT /Scans/{id}`) before starting the execution; if the server declines, a warning is emitted and the stored name is kept. Results, reports and gates behave identically in all scanning modes. A rescan against a scan that is already running is rejected by the server — use a `concurrency` group so the workflow never races itself.

---

## Quick start — simple DAST scan + monitor button

Two small files in your application repo give you the whole setup: a DAST button that scans and gates, and a Scan Monitor button for browsing history. Prerequisites: secrets `APPSCAN_KEY` / `APPSCAN_SECRET`, variables `APPSCAN_URL` / `APPSCAN_APP_ID`.

**`.github/workflows/dast.yml`** — the scan:

```yaml
name: DAST
on:
  workflow_dispatch:          # "Run workflow" button
  schedule:
    - cron: '0 2 * * *'       # nightly

concurrency:
  group: appscan-dast
  cancel-in-progress: false

jobs:
  dast:
    runs-on: [self-hosted, linux]   # or [self-hosted, windows] — the action supports both
    steps:
      - uses: actions/checkout@v4

      - name: AppScan 360 DAST
        id: dast
        uses: alexhcl/appscan360-dast-action@main
        env:
          ACCEPTSSL: "true"           # TLS skipped by default; set "false" to enforce verification
        with:
          baseurl:        ${{ vars.APPSCAN_URL }}
          asoc_key:       ${{ secrets.APPSCAN_KEY }}
          asoc_secret:    ${{ secrets.APPSCAN_SECRET }}
          application_id: ${{ vars.APPSCAN_APP_ID }}
          rescan_latest:  true                    # first run creates, then rescans
          starting_URL:   https://staging.yourapp.com   # used on the first run only
          wait_for_analysis: true
          fail_by_severity: true
          failure_threshold: High

      - name: Upload security report
        # Only upload when a report exists - a failed/timed-out scan leaves
        # report_file empty, and upload-artifact errors on an empty path.
        if: (success() || failure()) && steps.dast.outputs.report_file != ''
        uses: actions/upload-artifact@v4
        with:
          name: appscan-report-${{ github.run_number }}
          path: ${{ steps.dast.outputs.report_file }}
          if-no-files-found: ignore
```

**`.github/workflows/appscan-monitor.yml`** — the monitor button:

```yaml
name: "AppScan Scan Monitor"
on:
  workflow_dispatch:
    inputs:
      from_date:     { description: 'From date (yyyy-MM-dd)', required: false, default: '' }
      to_date:       { description: 'To date (yyyy-MM-dd, inclusive)', required: false, default: '' }
      scan_id:       { description: 'Exact scan ID', required: false, default: '' }
      name_contains: { description: 'Scan name contains (case-insensitive)', required: false, default: '' }
      max_reports:   { description: 'Max HTML reports to download (total)', required: false, default: '10' }
      per_execution: { description: 'One report per execution (default); uncheck for one per scan', required: false, default: true, type: boolean }

jobs:
  monitor:
    runs-on: [self-hosted, linux]   # or [self-hosted, windows] — the action supports both
    outputs:
      # JSON array of report filenames, emitted directly by the action.
      reports: ${{ steps.mon.outputs.monitor_report_files_json }}
    steps:
      - name: List past AppScan 360 scans
        id: mon
        uses: alexhcl/appscan360-dast-action@main
        env:
          ACCEPTSSL: "true"           # TLS skipped by default; set "false" here to enforce it
        with:
          baseurl:        ${{ vars.APPSCAN_URL }}
          asoc_key:       ${{ secrets.APPSCAN_KEY }}
          asoc_secret:    ${{ secrets.APPSCAN_SECRET }}
          application_id: ${{ vars.APPSCAN_APP_ID }}
          monitor: true
          monitor_from_date:     ${{ inputs.from_date }}
          monitor_to_date:       ${{ inputs.to_date }}
          monitor_scan_id:       ${{ inputs.scan_id }}
          monitor_name_contains: ${{ inputs.name_contains }}
          monitor_max_reports:   ${{ inputs.max_reports }}
          monitor_report_per_execution: ${{ inputs.per_execution }}

      # One bundle artifact with every report (download once, all inside).
      - name: Attach all reports (single bundle)
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: appscan-monitor-reports-${{ github.run_number }}
          path: 'AppScan_Monitor_Report-*.html'
          if-no-files-found: ignore

  # Publish each report as its OWN artifact, so every row in the Executions
  # table is downloadable separately from the run's Artifacts section.
  split:
    needs: monitor
    if: needs.monitor.outputs.reports != '' && needs.monitor.outputs.reports != '[]'
    runs-on: [self-hosted, linux]
    strategy:
      fail-fast: false
      matrix:
        report: ${{ fromJSON(needs.monitor.outputs.reports) }}
    steps:
      - name: Get the report bundle
        uses: actions/download-artifact@v4
        with:
          name: appscan-monitor-reports-${{ github.run_number }}
      - name: Publish ${{ matrix.report }} on its own
        if: matrix.report != ''
        uses: actions/upload-artifact@v4
        with:
          name: ${{ matrix.report }}
          path: ${{ matrix.report }}
          if-no-files-found: warn
```

Once both files are on the default branch, the Actions sidebar shows **DAST** and **AppScan Scan Monitor**, each with its own Run-workflow button — the monitor's filter fields render as a form (leave empty to list everything). Every DAST run's job summary already ends with the scan-history table (`scan_history`, on by default), so the monitor button is for filtered digs and report downloads.

**Downloading reports separately.** GitHub stores each `upload-artifact` as a single zip, so the first upload step gives you one `appscan-monitor-reports-*` bundle containing every HTML report. The `split` job then republishes **each report as its own artifact** (named after the file), so the run's **Artifacts** section lists them individually and you can download just the one you want. The report filenames come straight from the action's `monitor_report_files_json` output (a JSON array), which the matrix expands — no shell parsing, so it runs on Linux or Windows. Drop the `split` job if the single bundle is enough; it reuses the bundle rather than re-querying AppScan.

> **Runner labels:** set `runs-on` on **both** the `monitor` and `split` jobs to labels your runners actually have. If they differ (e.g. `monitor` on `windows`, `split` left on `linux`) the mismatched job hangs on "Waiting for a runner to pick up this job". The `split` job uses only `download-artifact`/`upload-artifact`, so it has no OS requirement of its own — match it to your fleet.

---

## Inputs

### Connection & authentication

| Input | Required | Default | Description |
|---|---|---|---|
| `baseurl` | yes | `https://your-appscan360-server` | Base URL of your AppScan 360° server. Every API call and portal link is built from it. |
| `asoc_key` | yes | — | API key ID (GitHub secret). |
| `asoc_secret` | yes | — | API key secret (GitHub secret). |
| `application_id` | yes | — | GUID of the AppScan application. |

> The credential inputs are `asoc_key` / `asoc_secret` — other names are dropped with an "unexpected input(s)" warning and login then fails with an empty-KeyId 400.

### Rescan

| Input | Default | Description |
|---|---|---|
| `rescan_latest` | `false` | **The rescan switch.** `true` → new execution of an existing scan instead of a new scan (see modes above). |
| `scan_id` | — | Optional override: the exact scan to rescan. Only used when `rescan_latest: true`. |

### Scan definition (new-scan mode only)

| Input | Default | Description |
|---|---|---|
| `dynamic_scan_type` | `dast` | `dast` = configure by URL + login inputs. `upload` = configure from an AppScan Standard file. |
| `scan_or_scant_file` | — | Path to the `.scan` or `.scant` file for `upload` mode. A full `.scan` carries config, login macro **and** explore data; a `.scant` template carries no explore data. Treat as a secret (it embeds credentials) — store base64 in a secret and materialize at runtime. |
| `scan_type` | *(server default)* | Upload mode only; sent as `TestOperation`. `FullScan` = continue Explore then Test. `TestOnly` = Test **only** the explore data in the file (test exactly your Manual Explore / Multi-Step Operations). `ReportOnly` = import the file's results without scanning. |
| `starting_URL` | testfire demo | Crawl entry point (`dast` mode). Point at **staging** — an authenticated scan submits forms and mutates data. |
| `scan_name` | generated | Scan display name, e.g. `GHA-${{ github.ref_name }}-${{ github.run_number }}`. |
| `optimization` | `Fastest` | `NoOptimization` · `Fast` · `Faster` · `Fastest`. |
| `login_method` | `none` | `none` · `userpass` · `recorded`. |
| `login_user` / `login_password` | — | Credentials for `userpass` (dedicated low-privilege scan account; no MFA/captcha in staging). |
| `login_sequence_file` | — | `recorded` mode: an AppScan Activity Recorder **DAST.CONFIG** file. A `.login` export from AppScan Standard is not supported — use the template/upload route. |

### Network & presence

| Input | Default | Description |
|---|---|---|
| `network` | `public` | `private` when scanners reach the target through an AppScan Presence (requires `presence_id`). |
| `presence_id` | — | Pre-created Presence ID. |
| `ephemeral_presence` | `false` | Deploy a temporary Presence in Docker on the runner for this job (forces `wait_for_analysis: true`). |

### Execution, results & post-scan hook

| Input | Default | Description |
|---|---|---|
| `wait_for_analysis` | `true` | `true` → wait, download the report, write the findings summary, evaluate gates. `false` → initiate only (no results, no gate; `gate_result: not_evaluated`). |
| `wait_for_analysis_timeout_minutes` | `360` | Max wait. **Exceeding it fails the job** (the scan keeps running on the server; link provided). |
| `post_scan_command` | — | Command to run after the scan — after results/gate in sync mode, right after initiation in async mode — see [Post-scan custom script](#post-scan-custom-script). |
| `github_token` | workflow token | Used by the action's post step to list this run's artifacts and append a **Downloads** section with direct artifact links to the summary (needs `actions: read`). Empty string disables it. |
| `scan_history` | `true` | Append a compact **Scan history** section (past scans + portal links, current run marked) to every scanning run's job summary. Set `false` to disable. |
| `scan_history_limit` | `15` | Max rows in the Scan history section. |
| `email_notification` | `false` | AppScan's built-in completion email (sent by the server's SMTP to the scan owner/subscribers; sets the scan's `EnableMailNotification`). Applies to new scans **and rescans**. Not a custom email — for that, send one yourself from `post_scan_command` or a workflow step. |
| `personal_scan` | `false` | Mark as a personal scan. |

### Security gates

| Input | Default | Description |
|---|---|---|
| `fail_by_severity` | `false` | Fail the job when open issues at or above `failure_threshold` are found. |
| `failure_threshold` | `High` | `Informational` < `Low` < `Medium` < `High` < `Critical`. E.g. `Medium` fails on Medium/High/Critical. |
| `fail_for_noncompliance` | `false` | Fail when the scan violates the application policy configured on the server. |

If no gate is enabled, the job passes regardless of findings — the action emits a warning and `gate_result: not_configured` so this is never silent.

### Monitor mode

| Input | Default | Description |
|---|---|---|
| `monitor` | `false` | `true` → list past scans and exit; nothing is scanned. Only connection inputs are needed. |
| `monitor_from_date` / `monitor_to_date` | — | Created-date range, `yyyy-MM-dd`, inclusive. |
| `monitor_scan_id` | — | Exact scan ID. |
| `monitor_name_contains` | — | Case-insensitive substring of the scan name. |
| `monitor_show_executions` | `true` | Also render an **Executions** table: each matched scan's executions (ID, created, status), newest first, for up to the 10 most recent matched scans. |
| `monitor_max_reports` | `10` | Max **total** HTML reports generated and downloaded (newest first); matches over the cap keep their Open-scan link. |
| `monitor_report_per_execution` | `true` | Download a report for **each execution** (the default). Reports appear in the Executions table's **Report** column, named `AppScan_Monitor_Report-<scan>-exec-<executionId>.html`; `monitor_max_reports` caps the total. Set to `false` for a single report per scan (its latest execution only). |

---

## Outputs

| Output | Meaning |
|---|---|
| `scan_id` / `execution_id` | Scan created or rescanned; execution started by this job (rescan mode). |
| `scan_url` | Portal deep link to the scan. |
| `scan_status` | `Ready` · `Failed` · `Stopped` · `TimedOut (…)` · `Running` (async). |
| `report_file` | Workspace filename of the HTML report (`AppScan_Security_Report-<sha>.html`). |
| `total_issues`, `critical_count`, `high_count`, `medium_count`, `low_count`, `informational_count` | Open-issue counts. |
| `gate_result` | `passed` · `failed` · `not_configured` · `not_evaluated` · `error`. |
| `monitor_matches` / `monitor_report_files` | Monitor mode: match count; downloaded report filenames (glob `AppScan_Monitor_Report-*.html`). |

**On the run page** you also get a **Downloads** section at the bottom of the job summary — direct download links (`…/actions/runs/<run>/artifacts/<id>`) for every artifact of the run, appended by the action's post step after `actions/upload-artifact` has published them (requires the default `github_token`). Additionally: a job summary (scan metadata + portal link, findings-by-severity table, top 20 issues, gate verdict, scan history), notice/warning/error annotations for every state change and failure (with the server's message), a timestamped status line in the log every 5 minutes while waiting, and — via `upload-artifact` — the HTML report(s).

---

## Post-scan custom script

`post_scan_command` runs in **both modes**, and a failing command only emits a warning — it never changes the gate verdict. It is executed by PowerShell on the runner, so any installed tool works (`curl`, `python`, …).

- **Sync (`wait_for_analysis: true`)** — runs **after** the scan completes and the gate is evaluated, **whether the gate passed or failed** (the job exits afterward), so notifications fire on red runs too. Full context is available (`ASOC_SCAN_STATUS=Ready`, counts, report file, gate result). Not run if the scan itself failed or timed out before results.
- **Async (`wait_for_analysis: false`)** — runs **right after the scan is initiated**, so you can notify that a scan started. The scan isn't finished, so `ASOC_SCAN_STATUS=Running` and the **result variables are empty** (no counts, no report, `ASOC_GATE_RESULT=not_evaluated`); the IDs, URL and name are set.

The scan context is exported as environment variables:

| Variable | Value | Async |
|---|---|---|
| `ASOC_SCAN_ID` / `ASOC_EXECUTION_ID` | Scan and (rescans) execution IDs | set |
| `ASOC_SCAN_URL` / `ASOC_SCAN_NAME` | Portal link, scan name | set |
| `ASOC_SCAN_STATUS` | `Ready` (sync) or `Running` (async) | `Running` |
| `ASOC_REPORT_FILE` | HTML report filename in the workspace | empty |
| `ASOC_TOTAL_ISSUES`, `ASOC_CRITICAL_COUNT`, `ASOC_HIGH_COUNT`, `ASOC_MEDIUM_COUNT`, `ASOC_LOW_COUNT`, `ASOC_INFORMATIONAL_COUNT` | Open-issue counts | empty |
| `ASOC_GATE_RESULT` | `passed` / `failed` / `not_configured` | `not_evaluated` |
| `ASOC_BASE_URL` / `ASOC_APP_ID` | For follow-up API calls | set |

Inline webhook (note the PowerShell `$env:` syntax in inline commands):

```yaml
post_scan_command: >-
  curl -s -X POST https://hooks.example.com/dast
  -H "Content-Type: application/json"
  -d "{\"scan\":\"$env:ASOC_SCAN_ID\",\"gate\":\"$env:ASOC_GATE_RESULT\",\"high\":$env:ASOC_HIGH_COUNT}"
```

Or a script from your repo (present after `actions/checkout`; inside the script use normal `os.environ` / `$ASOC_...`):

```yaml
post_scan_command: python3 scripts/notify.py
```

```python
# scripts/notify.py
import os, json, urllib.request
payload = {
    "scan": os.environ["ASOC_SCAN_ID"],
    "gate": os.environ["ASOC_GATE_RESULT"],
    "critical": int(os.environ["ASOC_CRITICAL_COUNT"]),
    "high": int(os.environ["ASOC_HIGH_COUNT"]),
    "url": os.environ["ASOC_SCAN_URL"],
}
req = urllib.request.Request("https://hooks.example.com/dast",
    data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
urllib.request.urlopen(req, timeout=10)
```

Keep secrets out of the command string — pass tokens via `env:` on the step, not pasted into the YAML.

The command runs in pwsh on whatever OS the runner is, so pick portable spellings: on Windows the Python launcher is usually `python` (not `python3`), and `curl` resolves to the real curl.exe on Windows 10+ as well as Linux. If a workflow targets both OSes, `python -c ...` and plain `curl` work everywhere.

---

## Sample workflow — all settings

`.github/workflows/dast.yml` in your application repo. Every input is shown; delete what you don't need (the commented alternatives show the other modes).

```yaml
name: DAST
on:
  schedule:
    - cron: '0 2 * * *'          # nightly at 02:00 UTC
  workflow_dispatch:              # Run-workflow button

concurrency:
  group: appscan-dast
  cancel-in-progress: false       # never two scans of the same target at once

jobs:
  dast:
    runs-on: [self-hosted, linux]   # or [self-hosted, windows] — the action supports both
    timeout-minutes: 300
    steps:
      - uses: actions/checkout@v4

      - name: AppScan 360 DAST
        id: dast
        uses: alexhcl/appscan360-dast-action@main
        env:
          ACCEPTSSL: "true"                  # TLS skipped by default; set "false" to enforce verification
        with:
          # ----- connection -----
          baseurl:        ${{ vars.APPSCAN_URL }}
          asoc_key:       ${{ secrets.APPSCAN_KEY }}
          asoc_secret:    ${{ secrets.APPSCAN_SECRET }}
          application_id: ${{ vars.APPSCAN_APP_ID }}

          # ----- mode: rescan the app's newest DAST scan (bootstraps on first run) -----
          rescan_latest:  true
          # scan_id: 413e0b6f-...              # pin the exact scan to rescan (optional)

          # ----- creation settings (used on the first run / with rescan_latest off) -----
          dynamic_scan_type: dast
          starting_URL:   https://staging.yourapp.com
          scan_name:      "GHA-${{ github.ref_name }}-${{ github.run_number }}"
          optimization:   Fastest
          login_method:   none
          # login_method: userpass
          # login_user:     ${{ secrets.SCAN_USER }}
          # login_password: ${{ secrets.SCAN_PASSWORD }}
          # login_method: recorded
          # login_sequence_file: login.dast.config
          # --- or configure from an AppScan Standard file instead: ---
          # dynamic_scan_type: upload
          # scan_or_scant_file: myapp-explored.scan
          # scan_type: TestOnly                # FullScan | TestOnly | ReportOnly

          # ----- network -----
          network: private
          presence_id: ${{ vars.APPSCAN_PRESENCE_ID }}
          # ephemeral_presence: true           # temp Presence in Docker on the runner

          # ----- execution & results -----
          wait_for_analysis: true
          wait_for_analysis_timeout_minutes: 240
          scan_history: true                   # past-scans table in every summary (default)
          scan_history_limit: 15
          email_notification: false
          personal_scan: false

          # ----- security gate -----
          fail_by_severity: true
          failure_threshold: High
          fail_for_noncompliance: false

          # ----- post-scan custom script -----
          post_scan_command: python3 scripts/notify.py

      - name: Upload security report
        # keep the report when the gate fails, but skip when the scan produced
        # none (empty report_file) so upload-artifact doesn't error on an empty path
        if: (success() || failure()) && steps.dast.outputs.report_file != ''
        uses: actions/upload-artifact@v4
        with:
          name: appscan-report-${{ github.run_number }}
          path: ${{ steps.dast.outputs.report_file }}
          if-no-files-found: ignore

      - name: Use results downstream
        if: always()
        run: |
          echo "Gate: ${{ steps.dast.outputs.gate_result }}"
          echo "Critical: ${{ steps.dast.outputs.critical_count }}  High: ${{ steps.dast.outputs.high_count }}"
          echo "Scan: ${{ steps.dast.outputs.scan_url }}"
```

## Sample workflow — scan monitor button

The monitor button workflow is shown in full in the [Quick start](#quick-start--simple-dast-scan--monitor-button) above, and ships in this repo as [`examples/appscan-monitor.yml`](examples/appscan-monitor.yml) — copy it to `.github/workflows/appscan-monitor.yml` in your application repo. Optional README badge for one-click access:

```markdown
[![AppScan scan monitor](https://img.shields.io/badge/AppScan-scan_monitor-2F5BEA)](https://github.com/<org>/<repo>/actions/workflows/appscan-monitor.yml)
```

---

## Python client — sync / async

For automation outside GitHub Actions, [`scripts/appscan_dast.py`](scripts/appscan_dast.py) drives the same API (standard library only, Python 3.8+). `--mode` decides how it works:

- **`--mode sync`** (default): start the scan or rescan, poll until it finishes, print issue counts, download the HTML report, and apply a severity gate (`--fail-on High` → exit code 1 on findings at/above High).
- **`--mode async`**: initiate the scan or rescan, print the scan/execution IDs and portal link, and exit immediately (exit 0).

```bash
# sync: wait, report, gate
python3 scripts/appscan_dast.py --base-url https://ascp.appscan.local \
  --app-id <APP_GUID> --rescan-latest --mode sync --fail-on High

# async: fire and forget
python3 scripts/appscan_dast.py --base-url https://ascp.appscan.local \
  --app-id <APP_GUID> --starting-url https://staging.yourapp.com --mode async
```

Credentials via `--key-id`/`--key-secret` or env `ASOC_KEY_ID`/`ASOC_KEY_SECRET`. Supports `--rescan-latest` (with optional `--scan-id` pin and `--scan-name` rename), new-scan creation with userpass login, `--timeout-minutes`, `--report-file`, and `--insecure` for TLS testing. Exit codes: 0 ok · 1 gate failed · 2 scan failed/stopped · 3 timeout · 4 connection/API error.

### Running it on Windows

Use `python` (the Windows launcher), **not** `python3` — on Windows `python3` is a Microsoft Store alias that errors with *"Python was not found"* when real Python isn't on that account's PATH:

```powershell
cd <repo>
$env:ASOC_KEY_ID='<key id>'; $env:ASOC_KEY_SECRET='<key secret>'

# SYNC - create/rescan, wait, pull counts, download report, apply gate:
python scripts\appscan_dast.py --base-url https://ascp.appscan.local `
  --app-id <APP_GUID> --rescan-latest --mode sync --fail-on High --insecure

# ASYNC - kick off and exit immediately:
python scripts\appscan_dast.py --base-url https://ascp.appscan.local `
  --app-id <APP_GUID> --rescan-latest --mode async --insecure
```

`--insecure` is the client's equivalent of the action's `ACCEPTSSL` (needed until the server CA is trusted). For a brand-new scan instead of a rescan, swap `--rescan-latest` for `--starting-url https://demo.testfire.net/`.

### Running it in a GitHub workflow

The Python client is a **standalone alternative** to the PowerShell action — it does the whole create/wait/report/gate itself, so you run it from a plain `python` step, not from `post_scan_command`. Copy `scripts/appscan_dast.py` into the repo that runs the workflow so `actions/checkout` makes it available.

Two notes for self-hosted runners:
- A runner running as a **Windows service** uses the service account's PATH, which usually has no usable Python (`python`/`python3` → *"Python was not found."*). `actions/setup-python` provides one regardless of the account.
- Use `shell: pwsh`, **not** `shell: bash` — Windows runners have no `bash` (PowerShell 7 is already required by the action).

Complete workflow showing **both modes** (a `mode` dropdown; the nightly schedule forces sync):

```yaml
name: "AppScan DAST (Python client)"
run-name: "AppScan DAST · ${{ github.event_name == 'schedule' && 'sync' || inputs.mode }}"

on:
  schedule:
    - cron: '0 2 * * *'            # nightly, always sync
  workflow_dispatch:
    inputs:
      mode:
        description: 'sync = wait + gate + report · async = start and exit'
        type: choice
        options: [sync, async]
        default: sync
      fail_on:
        description: '(sync) fail the job on open issues at/above this severity'
        type: choice
        options: [Critical, High, Medium, Low, Informational]
        default: High

concurrency:
  group: appscan-dast-python
  cancel-in-progress: false

jobs:
  dast:
    runs-on: [self-hosted, windows]   # match your runner's labels
    timeout-minutes: 360
    steps:
      - uses: actions/checkout@v4     # brings scripts/appscan_dast.py into the workspace
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: AppScan 360 DAST
        id: scan
        shell: pwsh                   # pwsh (not bash) — Windows runners have no bash
        env:
          ASOC_KEY_ID:     ${{ secrets.APPSCAN_KEY }}
          ASOC_KEY_SECRET: ${{ secrets.APPSCAN_SECRET }}
        run: |
          # Scheduled runs have no inputs -> force sync + High gate.
          $mode   = if ('${{ github.event_name }}' -eq 'schedule') { 'sync' } else { '${{ inputs.mode }}' }
          $failOn = if ('${{ github.event_name }}' -eq 'schedule') { 'High' } else { '${{ inputs.fail_on }}' }
          python scripts/appscan_dast.py `
            --base-url '${{ vars.APPSCAN_URL }}' `
            --app-id   '${{ vars.APPSCAN_APP_ID }}' `
            --rescan-latest `
            --mode $mode `
            --fail-on $failOn `
            --report-file "AppScan_Security_Report-${{ github.run_number }}.html" `
            --insecure
          # Exit code becomes the step result (pwsh fails the step on non-zero):
          #   0 ok (async started / sync passed) · 1 gate failed · 2 scan Failed/Stopped
          #   3 timeout · 4 API/connection error

      # Only sync produces a report; async exits before one exists.
      - name: Upload security report
        if: (success() || failure()) && (github.event_name == 'schedule' || inputs.mode == 'sync')
        uses: actions/upload-artifact@v4
        with:
          name: appscan-report-${{ github.run_number }}
          path: 'AppScan_Security_Report-*.html'
          if-no-files-found: ignore
```

**sync vs async at a glance:**

| | `--mode sync` (default) | `--mode async` |
|---|---|---|
| Waits for the scan | yes — polls every 30s to `Ready`/`Failed`/timeout | no — exits right after starting it |
| Downloads the report | yes (`--report-file`) | no |
| Applies the `--fail-on` gate | yes (exit 1 on findings at/above) | no (flag ignored) |
| Runner held for | the whole scan (minutes–hours) | seconds |
| Use it for | CI gates, nightly scans you act on | fire-and-forget kick-offs; collect later via monitor/portal |

For a brand-new scan instead of a rescan, drop `--rescan-latest` and add `--starting-url 'https://staging.yourapp.com'`. `--insecure` is the client's equivalent of `ACCEPTSSL` (skip TLS verification until the server CA is trusted).

### Action scan first, then the Python client

To run a normal gated DAST scan with the **action**, and **once it finishes** run the **Python client** (sync or async, chosen from a dropdown), put both in one job — steps run in order, so the client always starts after the action's scan completes. The nightly schedule uses an async follow-up.

```yaml
name: "AppScan DAST + Python follow-up"
run-name: "DAST + Python (${{ github.event_name == 'schedule' && 'async' || inputs.python_mode }})"

on:
  schedule:
    - cron: '0 2 * * *'
  workflow_dispatch:
    inputs:
      python_mode:
        description: 'Python client mode after the scan: sync (wait+gate+report) or async (start and exit)'
        type: choice
        options: [sync, async]
        default: async

concurrency:
  group: appscan-dast
  cancel-in-progress: false

jobs:
  dast:
    runs-on: [self-hosted, windows]   # match your runner's labels
    timeout-minutes: 360
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      # 1) Normal DAST scan via the action (sync: wait + gate + report)
      - name: AppScan 360 DAST (action)
        id: dast
        uses: alexhcl/appscan360-dast-action@main
        env:
          ACCEPTSSL: "true"
        with:
          baseurl:        ${{ vars.APPSCAN_URL }}
          asoc_key:       ${{ secrets.APPSCAN_KEY }}
          asoc_secret:    ${{ secrets.APPSCAN_SECRET }}
          application_id: ${{ vars.APPSCAN_APP_ID }}
          rescan_latest:     true
          wait_for_analysis: true
          fail_by_severity:  true
          failure_threshold: High

      - name: Upload the action's report
        if: (success() || failure()) && steps.dast.outputs.report_file != ''
        uses: actions/upload-artifact@v4
        with:
          name: appscan-action-report-${{ github.run_number }}
          path: ${{ steps.dast.outputs.report_file }}
          if-no-files-found: ignore

      # 2) After the scan finishes, run the Python client (sync|async)
      - name: Python client follow-up
        if: always()                  # run even if the gate above failed the job
        shell: pwsh                    # pwsh, not bash — Windows runners have no bash
        env:
          ASOC_KEY_ID:     ${{ secrets.APPSCAN_KEY }}
          ASOC_KEY_SECRET: ${{ secrets.APPSCAN_SECRET }}
        run: |
          $mode = if ('${{ github.event_name }}' -eq 'schedule') { 'async' } else { '${{ inputs.python_mode }}' }
          python scripts/appscan_dast.py `
            --base-url '${{ vars.APPSCAN_URL }}' `
            --app-id   '${{ vars.APPSCAN_APP_ID }}' `
            --rescan-latest --mode $mode --fail-on High `
            --report-file "AppScan_Python_Report-${{ github.run_number }}.html" `
            --insecure

      - name: Upload the Python client's report
        if: always() && inputs.python_mode == 'sync'   # async produces no report
        uses: actions/upload-artifact@v4
        with:
          name: appscan-python-report-${{ github.run_number }}
          path: 'AppScan_Python_Report-*.html'
          if-no-files-found: ignore
```

> This runs **two scans** of the application — the action's, then the client's. That's the point of chaining them here (gated primary scan, then a sync/async follow-up). If you only want **one** scan with something run afterwards, use the action's `post_scan_command` instead of a second tool.

### Run a script only when the gate fails

The action sets the `gate_result` output (`passed` / `failed` / `not_configured` / `not_evaluated` / `error`) **before** it exits, so you can trigger a follow-up step only on a failed gate. The gate failure makes the action step fail, so the follow-up step **must use `if: always()`** — otherwise GitHub skips it because a previous step failed. The output is still captured, so the condition evaluates correctly.

```yaml
      - name: AppScan 360 DAST (gated)
        id: dast
        uses: alexhcl/appscan360-dast-action@main
        env:
          ACCEPTSSL: "true"
        with:
          baseurl:        ${{ vars.APPSCAN_URL }}
          asoc_key:       ${{ secrets.APPSCAN_KEY }}
          asoc_secret:    ${{ secrets.APPSCAN_SECRET }}
          application_id: ${{ vars.APPSCAN_APP_ID }}
          rescan_latest:     true
          wait_for_analysis: true
          fail_by_severity:  true
          failure_threshold: High

      # Runs ONLY on a failed gate. always() is required (the step above failed).
      - name: On gate failure — run the Python client (sync or async)
        if: always() && steps.dast.outputs.gate_result == 'failed'
        shell: pwsh
        env:
          ASOC_KEY_ID:     ${{ secrets.APPSCAN_KEY }}
          ASOC_KEY_SECRET: ${{ secrets.APPSCAN_SECRET }}
        run: |
          $mode = '${{ inputs.on_fail_mode }}'        # 'sync' or 'async'
          python scripts/appscan_dast.py `
            --base-url '${{ vars.APPSCAN_URL }}' --app-id '${{ vars.APPSCAN_APP_ID }}' `
            --rescan-latest --mode $mode `
            --report-file "AppScan_OnFail_Report-${{ github.run_number }}.html" --insecure
```

- **sync** → the step waits for the follow-up scan and downloads its report; **async** → it starts the scan and returns immediately (the scan continues on the server).
- To run **your own** script instead (e.g. a notifier), swap the `python` line for `python scripts/on_gate_fail.py`. `ASOC_*` env vars are **not** set in this step (those exist only inside `post_scan_command`) — pass what it needs as arguments, e.g. `--high '${{ steps.dast.outputs.high_count }}'`.
- The job is already red because the gated scan step failed; the on-fail step running does not turn it green.

**Alternative — inside `post_scan_command`.** If you'd rather keep it in the action (no extra workflow step), `post_scan_command` runs on every completed scan and exposes `ASOC_GATE_RESULT`, so branch on it:

```yaml
          post_scan_command: >-
            pwsh -c "if ($env:ASOC_GATE_RESULT -eq 'failed') { python scripts/on_gate_fail.py --high $env:ASOC_HIGH_COUNT }"
```

A full ready-to-use workflow for the first pattern ships as [`examples/appscan-dast-on-gate-fail.yml`](examples/appscan-dast-on-gate-fail.yml).

## Example workflows

Ready-to-copy workflows live in [`examples/`](examples/) — drop one into `.github/workflows/` in your application repo and adjust `runs-on` labels / inputs:

| File | What it does |
|---|---|
| [`examples/dast.yml`](examples/dast.yml) | DAST scan + scan-history/monitor in one workflow, with a "Monitor only" and "Rescan latest" toggle. |
| [`examples/appscan-monitor.yml`](examples/appscan-monitor.yml) | Separate monitor button: lists past scans, downloads reports, and publishes **each report as its own artifact**. |
| [`examples/appscan-dast-python.yml`](examples/appscan-dast-python.yml) | The standalone Python client in **sync or async** mode (dropdown). |
| [`examples/appscan-dast-then-python.yml`](examples/appscan-dast-then-python.yml) | Action scan first, then the Python client (sync/async) once it finishes. |
| [`examples/appscan-dast-on-gate-fail.yml`](examples/appscan-dast-on-gate-fail.yml) | Run the Python client (sync/async) **only when the security gate fails**. |

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `spawn pwsh ENOENT` | PowerShell 7 missing from the runner (or not on the service PATH). Install it, restart the runner service. |
| "Unexpected input(s) …" warning | Input name typo — the warning lists the valid names. Credentials under wrong names → empty-KeyId 400 at login. |
| `UntrustedRoot` certificate error | Only appears if you enforced TLS with `ACCEPTSSL: "false"` (TLS is skipped by default). The runner doesn't trust the server's CA **in that OS's store** — installing it on one runner does not cover another. Linux: `update-ca-certificates`. Windows: import into `Cert:\LocalMachine\Root`. Then keep `ACCEPTSSL: "false"`. |
| 400 "KeyId field is required" | Credentials arrived empty — check secret names and the `asoc_key`/`asoc_secret` input names. |
| Rescan rejected | The scan is already running on the server, or the scan ID is wrong / not visible to the API key. |
| Scan "succeeds" but finds almost nothing | Login macro silently broken — check explored URLs in the portal, re-record the login. |
| Job fails at the timeout | Raise `wait_for_analysis_timeout_minutes`, reduce scope, or use a faster `optimization`. The scan continues on the server (link in the error). |
| Cancelled workflow | The post-job step stops the server-side execution automatically — no orphan scans. |
| `python3` / `post_scan_command` fails with "Python was not found" | The runner (as a service) has no real Python on its PATH — only the Windows Store alias. Use `actions/setup-python`, call `python` with a full path, or don't shell Python from `post_scan_command`; run the standalone `scripts/appscan_dast.py` with setup-python instead. |
| No Downloads section in the summary | The post step needs `github_token` with `actions: read` (the default workflow token has it unless the workflow sets restrictive `permissions:`). Its log line states the reason. |
| `ephemeral_presence` fails on Windows | The presence image is a Linux container. Use a Linux runner for that feature, or a pre-created `presence_id`. |
| `Scan creation failed (POST /Scans/Dast)` | The action now surfaces the server's full JSON reason — read it. Most common: the target domain is **not verified** in AppScan 360 (verify it, or point `starting_URL` at a verified target such as `https://demo.testfire.net`); a `rescan_latest` run on an app with no scan yet and no `starting_URL`; or a bad `application_id`. |
| `Input required and not supplied: path` (upload-artifact) | The `path` expression was empty. On the DAST workflow this means the scan failed/timed out so `report_file` is empty — guard the upload with `if: (success() \|\| failure()) && steps.dast.outputs.report_file != ''`. The templates above already do this. |
| Monitor `split` step: `bash: command not found` | An older monitor workflow built its file list with a `shell: bash` step; Windows self-hosted runners have no bash. Use the current monitor workflow, which has **no shell step** — it reads the report list from the action's `monitor_report_files_json` output instead. |
| Monitor `split` job stuck on "Waiting for a runner to pick up this job" | `runs-on` label mismatch: the job is requesting labels (e.g. `self-hosted, linux`) that none of your runners have. Set **both** the `monitor` and `split` jobs' `runs-on` to match your runner (e.g. `[self-hosted, windows]`). |

## License

Licensed under Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
