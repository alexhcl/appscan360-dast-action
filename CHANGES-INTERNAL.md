# Internal fork changes — scan visibility, results, and CI/CD gating

This fork addresses the review feedback that the action "only initiates a scan"
with no status, results, or pipeline gating visible to developers.

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
