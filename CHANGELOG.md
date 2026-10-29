# Internal fork changes — scan visibility, results, and CI/CD gating

This fork addresses the review feedback that the action "only initiates a scan"
with no status, results, or pipeline gating visible to developers.

## Recent changes (2026-10-29)
- **Monitor: report per execution.** Monitor mode now generates and downloads an
  HTML report for **each execution** of the matched scans (verified endpoint
  `POST /api/v4/Reports/Security/ScanExecution/{id}`), shown in the Executions
  table's new **Report** column. Controlled by `monitor_report_per_execution`,
  **enabled by default**; set it to `false` for one report per scan.
  `monitor_max_reports` caps the total.
- **Monitor: per-file downloads.** The sample monitor workflow now republishes
  each report as its own artifact (matrix `split` job), so every report is
  downloadable separately from the run's Artifacts section.
- **TLS skipped by default (security note).** `ACCEPTSSL` now defaults to
  `"true"`, so certificate verification is **skipped unless you opt back in**
  with `ACCEPTSSL: "false"`. This avoids per-runner CA-trust failures but is
  insecure (accepts any certificate, exposes the API key). Trust the server CA
  on the runner and set `ACCEPTSSL: "false"` for production.

## What was added

### 1. Scan status tracking and completion notification
- Timestamped progress lines every 5 minutes while waiting (status, % progress, elapsed time).
- Workflow **notice annotation** when the scan starts and when it completes.
- **New failure detection**: `Stopped` scans and Paused scans are now handled
  (previously only `Failed` was). Paused scans emit a warning annotation.
- **Timeout is now a failure**: previously, a scan that exceeded
  `wait_for_analysis_timeout_minutes` silently continued into report
  generation as if it had succeeded. It now fails the job with a clear
  error and a link to the still-running scan.

### 2. Failure/error visibility in the workflow
- All failure paths (scan creation failure, scan Failed/Stopped, timeout,
  gate failures) emit `::error::` annotations — visible on the run page
  without opening logs — including the server's error message and a deep
  link to the scan's execution log.
- Cancelled workflows write a summary note confirming the server-side scan
  was stopped.

### 3. Scan results inside GitHub Actions
- A **job summary** (run page, no dashboard access needed) is written with:
  scan metadata + portal link, findings-by-severity table, top 20 issues
  (severity, type, location, status), gate verdict, and report location.
- The HTML security report keeps downloading to the workspace; its filename
  is now deterministic (`AppScan_Security_Report-<sha>.html`) and exposed
  as an output for `actions/upload-artifact`.

### 4. Pipeline gating on scan outcome
- The existing `fail_by_severity`/`failure_threshold` and
  `fail_for_noncompliance` gates are kept and now surface an explicit
  PASSED/FAILED verdict in the summary and annotations.
- If **no gate is configured**, the action emits a warning so teams don't
  mistakenly believe findings would fail the build.
- New `gate_result` output for branch protection / downstream automation.

### 5. Step outputs (new in action.yml)
| Output | Meaning |
|---|---|
| `scan_id` / `scan_url` | Scan identifier and portal deep link |
| `scan_status` | `Ready`, `Failed`, `Stopped`, `TimedOut (...)`, `Running` |
| `report_file` | Filename of the downloaded HTML report |
| `total_issues`, `critical_count`, `high_count`, `medium_count`, `low_count`, `informational_count` | Open-issue counts |
| `gate_result` | `passed` / `failed` / `not_configured` / `not_evaluated` / `error` |

## Files changed
- `github.ps1` (new): job summary / outputs / annotation helpers + severity aggregation.
- `asoc.ps1`: sources github.ps1; rewritten `Run-ASoC-ScanCompletionChecker`;
  `Run-ASoC-DownloadReport` returns a deterministic filename.
- `main.ps1`: outputs + summary at every stage; explicit gate verdicts;
  async (`wait_for_analysis: false`) runs now report `not_evaluated`.
- `cancelJob.ps1`: cancellation note in summary.
- `action.yml`: `outputs:` block declared.

## Requirements for full value
- Run with `wait_for_analysis: true` — with `false`, the action can only
  initiate the scan (this is now clearly labeled in the summary instead of
  silently succeeding).
- Enable a gate: `fail_by_severity: true` + `failure_threshold: High` (or
  `fail_for_noncompliance: true`).
- Add `actions/upload-artifact` for the report so developers can download it
  from the run page.

## Rescan support (added)

### New input: `scan_id`
When `scan_id` is provided, the action triggers a **rescan** — a new
execution of that existing scan via `POST /Scans/{scanId}/Executions` —
instead of creating a new scan. The scan's stored configuration, target
and login macro on the server are reused; scan-creation inputs
(scan file/template, `starting_URL`, `login_*`) are ignored in this mode.

Benefits over creating a new scan every run:
- Issue history and trending stay on one scan in the portal.
- No scan sprawl (one scan per app/environment, many executions).
- No template re-upload per run; faster job start.
- Triage state (issue statuses, comments) carries across runs.

Everything downstream is identical: status tracking, job summary,
outputs, report download, and security gates all run against the scan
after the new execution completes.

### New output: `execution_id`
The ID of the execution started by this job (rescan mode).

### Polling fix that rescans made necessary
`GET /Scans/{id}/Executions` returns ALL executions of a scan. The wait
loop now tracks the execution this job started (falling back to the most
recent), so an old Failed or Ready execution can no longer wrongly fail
or complete the job. This also hardens new-scan mode.

### Recommended pattern
- One-time setup: create the scan once (template upload run, or manually
  in the portal) and record its scan ID as a repository variable.
- Pipeline runs: pass `scan_id: ${{ vars.APPSCAN_SCAN_ID }}` for rescans.
- When the login macro or scan config changes: update the scan on the
  server (or run once in creation mode) — pipeline stays untouched.

## scan_id: "latest" (added)
`scan_id` now accepts the keyword `latest`: the action queries the server
for the application's scans, filters to DAST (`Technology eq
DynamicAnalyzer`, when the property exists), picks the newest by
`CreatedAt` (client-side sort for cross-version robustness), and rescans
it. If the application has no scan yet, it falls back to creating a new
scan using the normal creation inputs - so one workflow bootstraps itself:
first run creates, every later run rescans. The resolved scan name/ID is
printed in the log and shown in the job summary.

### Update: auto-rescan is now flag-gated
The "latest" keyword on scan_id was replaced by an explicit boolean input
`rescan_latest` (default false). Auto-resolution of the newest DAST scan
only happens when the flag is enabled; scan_id remains a plain GUID and
takes precedence if both are set. First-run fallback to scan creation is
unchanged.

### Final rescan semantics (v2.1.x)
`rescan_latest: true` is the ONLY switch that triggers a rescan:
- flag on, scan_id empty -> auto-resolve and rescan the app's most recent
  DAST scan (first-run fallback: create a new scan)
- flag on, scan_id set   -> rescan exactly that scan (explicit override)
- flag off               -> always create a new scan; a provided scan_id
  is ignored with a warning

## scan_type input (added)
New optional input `scan_type` for upload mode (dynamic_scan_type: upload):
- FullScan  : continue Explore (adds to the file's explore data), then Test
- TestOnly  : Test stage ONLY, on the explore data already in the uploaded
              .scan (Manual Explore / Multi-Step Operations) - precise-scope,
              faster scans of exactly what was recorded
- ReportOnly: import the file's results without scanning
Empty (default) sends nothing and keeps the server default. Sent as the
TestOperation field of POST /api/v4/Scans/Dast alongside ScanOrTemplateFileId.
Note: a .scant template carries no explore data - use a full .scan file
with TestOnly.

## v2.3.0 - post-scan command + monitor mode

### post_scan_command (added)
New input: a command (curl webhook, python3 script, any runner tool) executed
after the scan completes and results/gates are evaluated, with full context
as ASOC_* environment variables (scan/execution IDs, portal URL, report file,
severity counts, gate verdict, base URL, app ID). Runs whether the gate
passed or failed - the job exits AFTER it - and a failing command only warns,
never changing the gate verdict. Requires wait_for_analysis: true; skipped
with a warning on async runs; not run for failed/timed-out scans.
Internally the gate section was refactored: both gates record their verdict
first and the job exits at the end, so the hook always sees the final
ASOC_GATE_RESULT.

### monitor mode (added)
New inputs: monitor (the switch), monitor_from_date, monitor_to_date
(yyyy-MM-dd, inclusive), monitor_scan_id (exact), monitor_name_contains
(case-insensitive substring), monitor_max_reports (default 10).
With monitor: true the action lists the application's past scans (newest
first) in the job summary - active filters, match count, and per scan:
created date, name, ID, latest status, an Open-scan portal link, and the
scan's HTML report downloaded to the workspace (named
AppScan_Monitor_Report-<name>-<id>.html; attach with upload-artifact using
path: AppScan_Monitor_Report-*.html). New outputs: monitor_matches,
monitor_report_files. Monitor mode needs only baseurl, credentials and
application_id; no scan is created or executed.

### internal
Run-ASoC-DownloadReport now accepts an optional output filename;
Run-ASoC-GetScansForApp and Select-MonitorScans added (filter logic is a
pure function covered by smoke tests).

## v2.4.0 - always-on scan history + monitor button workflow

### scan_history (added, default ON)
Every scanning run now appends a compact "Scan history" section to the job
summary: the application's past scans, newest first, with created date,
name, ID, latest status and an Open-scan portal link per scan; the current
run's scan is marked "(this run)". Links only - one extra GET, no report
generation. New inputs: scan_history (default true; set false to disable),
scan_history_limit (default 15; over-limit scans are summarized by a count
pointing to monitor mode). Rendered on both wait and async runs; skipped
safely when the app has no scans or the fetch fails (warning only).

### Monitor button workflow (companion file)
appscan-monitor.yml: a workflow_dispatch workflow that surfaces monitor
mode as a "Run workflow" button in the repo's Actions tab, with the filters
(from/to date, scan id, name contains, max reports) as form fields.
Reports attach as a run artifact. Install into the app repo at
.github/workflows/appscan-monitor.yml; optional README badge links to it.

### README rewritten (v2.4.x)
Full repo documentation: requirements (PowerShell 7, TLS/CA), operating
modes, every input/output with defaults, post_scan_command with the ASOC_*
variable table and examples, an all-settings sample workflow, the monitor
button workflow, and a troubleshooting table.

## v2.4.1 - Linux + Windows runner support

### Security: removed verbose environment logging
Diagnostic logging that printed the full process environment (which could
include the API key and secret) on every run was removed, so credentials no
longer appear in run logs.

### Cross-platform
- The scripts were already OS-portable (pwsh, slash-normalized paths); the
  one real per-OS requirement is TLS trust: pwsh validates against each OS's
  own store. Linux: update-ca-certificates. Windows: import the CA into
  Cert:\LocalMachine\Root (Import-Certificate or certutil).
- ephemeral_presence now warns on non-Linux runners (the presence image is a
  Linux container); action.yml description updated.
- Startup now logs the runner OS instead of the environment.
- README: Windows install/CA-trust block, OS-aware requirements and
  troubleshooting rows, runs-on label guidance, python vs python3 note for
  post_scan_command.

## v2.4.2 - clickable report links in the summary
Monitor-table Report cells and the completed-scan report line are now links
to the run's Artifacts section (run URL + #artifacts anchor), where the
upload-artifact step publishes the HTML reports as a downloadable zip.
GitHub offers no per-file URLs inside an artifact, so the anchor is the
closest possible direct link; a direct link to the zip itself can be added
by the workflow via upload-artifact v4's artifact-url output (README).

## v2.5.0 - executions view, direct downloads, rescan polish, Python client

### Monitor: executions listed too
Monitor mode renders an Executions table after the Scans table: each matched
scan's executions (ID, created, status), newest first, for up to the 10 most
recent matched scans. New input monitor_show_executions (default true).

### Direct artifact download links (fixes the two-URL confusion)
The post step now runs on EVERY job (previously only on cancellation):
 1. stops the scan execution on the server only when it is still running
    (summary note written before the call, so it survives server errors);
 2. lists this run's artifacts via the GitHub API (new github_token input,
    default: the workflow token) and appends a "Downloads" section to the
    job summary with DIRECT links (.../actions/runs/<run>/artifacts/<id>)
    - clickable downloads, not just the #artifacts anchor.
Login-ASoC gained -SoftFail so post-step failures never fail a green job.

### Rescan polish
- starting_URL is no longer displayed for rescans (summary shows "(from the
  scan's stored configuration)"); the main.js startup URL log was removed.
- scan_name is now honored on rescans: best-effort rename via
  PUT /Scans/{id} before the execution starts; server refusal only warns.
- The requested scan name is logged at startup for traceability.

### Python client (scripts/appscan_dast.py)
Stdlib-only CLI mirroring the action over the same API. --mode sync waits,
prints counts, downloads the report and applies a --fail-on severity gate;
--mode async initiates and exits. Supports rescan-latest/scan-id/scan-name,
userpass login, timeout, --insecure. Exit codes 0/1/2/3/4.

## v2.5.2 - scan-creation errors report their cause, Python client docs
README Python client section expanded: Windows usage (`python` not `python3`,
the Store-alias trap), a GitHub-workflow example using actions/setup-python
(self-hosted-as-service runners lack the interactive user's Python on PATH),
`--insecure` = ACCEPTSSL, and a troubleshooting row for "Python was not found".

Run-ASoC-DynamicAnalyzerAPI (POST /Scans/Dast) now wraps the call and
surfaces the server's response body (ErrorDetails.Message) plus the common
causes (unverified target domain, presence required, licence/scan limit),
instead of a truncated "Invoke-RestMethod: asoc.ps1:224".

## v2.5.1 - stale workspace cleanup + clear login errors

### Login errors now name their cause
Login-ASoC wraps the API call: on failure the run log and an ::error::
annotation carry the full exception (inner SSL/DNS exception included)
plus remediation hints, instead of a truncated "Invoke-RestMethod: line NN".
Note for Windows runners AS A SERVICE: the CA must be in
Cert:\LocalMachine\Root - an import into the interactive user's store
stops working when the runner runs under a service account.

### stale workspace cleanup
main.ps1 now deletes this action's leftovers from previous runs at startup
(scanid.txt, ephemeralPresenceId.txt, AppScan_Security_Report-*.html,
AppScan_Monitor_Report-*.html). On self-hosted runners the workspace
persists between runs, so a failed run could previously upload an OLD
report as its artifact and the post step could inspect a stale scan id.
