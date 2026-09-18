# github.ps1 - Helpers to surface scan status/results inside GitHub Actions
# (job summary, step outputs, workflow annotations)

function Set-GHOutput($name, $value){
  # Exposes a value as a step output: consumable via steps.<id>.outputs.<name>
  if(-not [string]::IsNullOrEmpty($env:GITHUB_OUTPUT)){
    Add-Content -Path $env:GITHUB_OUTPUT -Value "$name=$value"
  }
  Write-Debug "Output set: $name=$value"
}

function Add-GHSummary($markdown){
  # Appends markdown to the job summary rendered on the workflow run page
  if(-not [string]::IsNullOrEmpty($env:GITHUB_STEP_SUMMARY)){
    Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value $markdown
  }
}

function Write-GHError($message){
  # Red error annotation on the workflow run (visible without opening logs)
  Write-Host "::error title=AppScan DAST::$message"
}

function Write-GHWarning($message){
  Write-Host "::warning title=AppScan DAST::$message"
}

function Write-GHNotice($message){
  Write-Host "::notice title=AppScan DAST::$message"
}

function Get-SeverityCounts($issueCountJson){
  # Normalizes the grouped issue-count payload into totals per severity.
  # The API groups by (Status,Severity); sum across statuses. The count
  # property may surface as N (aggregate alias) or Count depending on version.
  $counts = [ordered]@{ Critical = 0; High = 0; Medium = 0; Low = 0; Informational = 0 }
  foreach($i in $issueCountJson){
    $n = 0
    if($null -ne $i.PSObject.Properties['N'])          { $n = [int]$i.N }
    elseif($null -ne $i.PSObject.Properties['Count'])  { $n = [int]$i.Count }
    if($null -ne $i.Severity -and $counts.Contains([string]$i.Severity)){
      $counts[[string]$i.Severity] += $n
    }
  }
  return $counts
}

function Add-GHSeveritySummaryTable($counts, $total){
  Add-GHSummary "### Findings by severity`n"
  Add-GHSummary "| Severity | Open issues |"
  Add-GHSummary "|---|---|"
  Add-GHSummary ("| :red_circle: Critical | {0} |" -f $counts['Critical'])
  Add-GHSummary ("| :orange_circle: High | {0} |" -f $counts['High'])
  Add-GHSummary ("| :yellow_circle: Medium | {0} |" -f $counts['Medium'])
  Add-GHSummary ("| :white_circle: Low | {0} |" -f $counts['Low'])
  Add-GHSummary ("| :information_source: Informational | {0} |" -f $counts['Informational'])
  Add-GHSummary ("| **Total** | **{0}** |`n" -f $total)
}

function Add-GHTopIssuesTable($issueItems, $maxRows){
  # Renders the top issues (sorted most-severe first) into the job summary
  if($null -eq $issueItems -or $issueItems.Count -eq 0){
    Add-GHSummary "_No open issues were reported for this scan._`n"
    return
  }
  $sorted = $issueItems | Sort-Object -Property @{Expression={ Get-SeverityValue($_.Severity) }; Descending=$true}
  $shown = $sorted | Select-Object -First $maxRows

  Add-GHSummary "### Top issues`n"
  Add-GHSummary "| Severity | Issue type | Location | Status |"
  Add-GHSummary "|---|---|---|---|"
  foreach($i in $shown){
    $type = $i.IssueType
    if([string]::IsNullOrEmpty($type)){ $type = $i.IssueTypeId }
    $loc = $i.Location
    if([string]::IsNullOrEmpty($loc)){ $loc = $i.Url }
    # keep the summary table readable
    if($loc -and $loc.Length -gt 80){ $loc = $loc.Substring(0,77) + "..." }
    Add-GHSummary ("| {0} | {1} | {2} | {3} |" -f $i.Severity, $type, $loc, $i.Status)
  }
  if($issueItems.Count -gt $maxRows){
    Add-GHSummary ("`n_Showing {0} of {1} issues. The full list is in the attached HTML report and the AppScan portal._`n" -f $maxRows, $issueItems.Count)
  } else {
    Add-GHSummary ""
  }
}
