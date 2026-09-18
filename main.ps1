# Copyright 2023, 2024 HCL America
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

Write-Host "Starting ASoC script"

$Os = 'linux'
if($IsMacOS){
  $Os = 'mac'
}elseif($IsWindows){
  $Os = 'win'
}

#DEBUG - To show DEBUG Messages, set $DebugPreference = 'Continue'


#$DebugPreference = 'Continue'
$DebugPreference = 'SilentlyContinue'

Write-Debug "Print environment variables:"
Write-Host "github.sha: " $env:GITHUB_SHA
ls -l .
dir env:

#[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#INITIALIZING VARIABLES
$global:BearerToken = ""
$global:scan_name = ''
if([string]::IsNullOrEmpty($env:INPUT_SCAN_NAME)){
  $global:scan_name = "$env:GITHUB_REPOSITORY $env:GITHUB_SHA"
}else{
  $global:scan_name = "$env:INPUT_SCAN_NAME"
}
$global:jsonBodyInPSObject = ""
$global:scanId = ""
$env:scanId = ""
$global:BaseAPIUrl = ""
$global:BaseAPIUrl = $env:INPUT_BASEURL + "/api/v4"
Write-Debug $global:BaseAPIUrl
$global:ephemeralPresenceId = ""
$global:GithubRunURL = "$env:GITHUB_SERVER_URL/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID"
Write-Host "Gitub Run URL: $global:GithubRunURL"
$scanidFileName = ".\scanid.txt"
$ephemeralPresenceIdFileName =".\ephemeralPresenceId.txt"
$global:ephemeralPresenceName = "Github Runner $env:RUNNER_TRACKING_ID"

#${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}

#INITIALIZE
#Construct base JSON Body for DAST Scan for API DynamicAnalyzer and DynamicAnalyzerWithFiles
$global:jsonBodyInPSObject = @{
  IncludeVerifiedDomains = $true
  ScanConfiguration = @{
    Target = @{
      'StartingUrl' = $env:INPUT_STARTING_URL
    }

    Tests = @{
      'TestOptimizationLevel' = $env:INPUT_OPTIMIZATION
    }
  }
  UseAutomaticTimeout = $true
  MaxRequestsIn = 10
  MaxRequestsTimeFrame = 1000
  OnlyFullResults = $true
  FullyAutomatic = $true
  ScanName = $global:scan_name
  EnableMailNotification = [System.Convert]::ToBoolean($env:INPUT_EMAIL_NOTIFICATION)
  Locale = 'en-US'
  AppId = $env:INPUT_APPLICATION_ID
  Execute = $true
  Personal = [System.Convert]::ToBoolean($env:INPUT_PERSONAL_SCAN)
  ClientType = "github-dast-$Os-$env:GITHUB_ACTION_REF"
}

#LOAD ALL ASOC FUNCTIONS FROM LIBRARY FILE asoc.ps1
. "$env:GITHUB_ACTION_PATH/asoc.ps1"
#MAIN
Login-ASoC

#if ephemeral_presence is set to true, we will proceed to set our own presence settings and ignore other presence related settings on the YAML
if($env:INPUT_EPHEMERAL_PRESENCE -eq $true){
  
  Create-EphemeralPresenceWithDocker
  Write-Debug "Ephemeral Presence Id: $global:ephemeralPresenceId"
  $global:jsonBodyInPSObject.Add("PresenceId",$global:ephemeralPresenceId)

  #Save ephemeralPresence ID in a file
  $global:ephemeralPresenceId | Out-File -FilePath $ephemeralPresenceIdFileName -Force


}else{
  #CHECK NETWORK setting, if private, then set presence ID to the one on the YAML config
  Set-AppScanPresence
}

#Run DAST Scan: create a new scan, or RESCAN when rescan_latest is enabled.
#rescan_latest: true is the only switch that triggers a rescan. The scan to
#rescan is auto-resolved (the application's most recent DAST scan), unless
#scan_id is provided as an explicit override of which scan to rescan.
$global:executionId = ''
$scanMode = 'New scan'
$requestedScanId = ''

if($env:INPUT_RESCAN_LATEST -eq $true){
  if(-not [string]::IsNullOrEmpty($env:INPUT_SCAN_ID)){
    $requestedScanId = $env:INPUT_SCAN_ID
    Write-Host "rescan_latest enabled with explicit scan_id override - rescanning scan: $requestedScanId"
  } else {
    Write-Host "rescan_latest is enabled - looking up the most recent DAST scan for application $env:INPUT_APPLICATION_ID ..."
    $resolvedId = Run-ASoC-GetLatestScanIdForApp($env:INPUT_APPLICATION_ID)
    if([string]::IsNullOrEmpty($resolvedId)){
      Write-GHNotice "rescan_latest: no existing scan found for this application - creating a new scan instead (first run)."
      $requestedScanId = ''
    } else {
      $requestedScanId = $resolvedId
    }
  }
}elseif(-not [string]::IsNullOrEmpty($env:INPUT_SCAN_ID)){
  Write-GHWarning "scan_id was provided but rescan_latest is not enabled - a NEW scan will be created and scan_id is ignored. Set rescan_latest: true to rescan."
}

if(-not [string]::IsNullOrEmpty($requestedScanId)){
  $scanMode = 'Rescan'
  $global:scanId = $requestedScanId
  Write-Host "Triggering a RESCAN (new execution) of existing scan: $global:scanId"
  Write-Host "Rescan mode reuses the scan's stored configuration, target and login macro on the server."
  Write-Host "Inputs for scan creation (scan file/template, starting_URL, login_*) are ignored in this mode."

  $global:executionId = Run-ASoC-Rescan($global:scanId)

  if([string]::IsNullOrEmpty($global:executionId)){
    Set-GHOutput 'gate_result' 'error'
    Write-GHError "Rescan failed - no execution ID was returned for scan '$global:scanId'. Verify the scan exists, belongs to application_id, is not already running, and the API key can access it."
    Add-GHSummary "## :x: AppScan DAST rescan could not be started`n"
    Add-GHSummary "``POST /Scans/$global:scanId/Executions`` returned no execution ID. Check that the scan ID is valid, not currently running, and visible to this API key.`n"
    Write-Error "Rescan failed - empty execution ID."
    exit 1
  }
  Set-GHOutput 'execution_id' $global:executionId
  Write-Host "New execution started with ID: $global:executionId"
}else{
  $global:scanId = Run-ASoC-DAST
}

if([string]::IsNullOrEmpty($global:scanId)){
  Set-GHOutput 'gate_result' 'error'
  Write-GHError "Scan creation failed - no scan ID was returned by the server. Check credentials, application_id, baseurl and presence settings."
  Add-GHSummary "## :x: AppScan DAST scan could not be created`n"
  Add-GHSummary "No scan ID was returned by ``$global:BaseAPIUrl/Scans/Dast``. Verify API key/secret, ``application_id``, ``baseurl`` and (for private networks) the Presence.`n"
  Write-Error "Scan creation failed - empty scan ID."
  exit 1
}

#Save Scan ID in a file
$global:scanId | Out-File -FilePath $scanidFileName -Force

#Display ASoC Scan URL
$scanOverviewPage = $env:INPUT_BASEURL + "/main/myapps/" + $env:INPUT_APPLICATION_ID + "/scans/" + $global:scanId
Write-Host "Scan is initiated and can be viewed in ASoC Scan Dashboard:" 
Write-Host $scanOverviewPage -ForegroundColor Green

#Expose scan identifiers to the rest of the workflow
Set-GHOutput 'scan_id' $global:scanId
Set-GHOutput 'scan_url' $scanOverviewPage
Write-GHNotice "DAST scan initiated. Scan ID: $global:scanId - $scanOverviewPage"

#Start the job summary
Add-GHSummary "# AppScan 360 DAST scan`n"
Add-GHSummary "| | |"
Add-GHSummary "|---|---|"
Add-GHSummary "| **Mode** | $scanMode |"
Add-GHSummary "| **Scan name** | $global:scan_name |"
Add-GHSummary "| **Scan ID** | ``$global:scanId`` |"
if(-not [string]::IsNullOrEmpty($global:executionId)){
  Add-GHSummary "| **Execution ID** | ``$global:executionId`` |"
}
Add-GHSummary "| **Target** | $env:INPUT_STARTING_URL |"
Add-GHSummary "| **Commit** | ``$env:GITHUB_SHA`` |"
Add-GHSummary "| **Scan view** | $scanOverviewPage |`n"

#IF ephemeral Presence is set, we must force set wait_for_analysis to true regardless of what the user has set. 
if($env:INPUT_EPHEMERAL_PRESENCE -eq $true){
  Write-Host "Since ephemeral_presence is true, wait_for_analysis will be set to true even if it was not set by user. This is required to keep the runner active and therefore keeps the ephemeral presence alive. "
  $env:INPUT_WAIT_FOR_ANALYSIS = $true
}

#If wait_for_analysis is set to true, we proceed to wait for scan completion, then performs report generation
if($env:INPUT_WAIT_FOR_ANALYSIS -eq $true){

  #Check for scan completion. The process pauses until scan is complete or timeout value has reached
  Run-ASoC-ScanCompletionChecker ($global:scanId)

  #As soon as the scan is complete, we kill the ephemeral presence if one was set
  if($env:INPUT_EPHEMERAL_PRESENCE -eq $true){
    Write-Host "Deleting ephemeral presence with ID: $global:ephemeralPresenceId"
    Run-ASoC-DeletePresence($global:ephemeralPresenceId)
  }

  #Update comment on ASoC issues
  $issueJson = Run-ASoC-GetAllIssuesFromScan($global:scanId)
  $issueItems = $issueJson.Items
  foreach($i in $issueItems){
    $issueId = $i.Id
    Write-Host "Writing Comments for Issue ID: $issueId"
    Run-ASoC-SetCommentForIssue $scanId $issueId "Issue found during Scan from Github SHA: $env:GITHUB_SHA, URL: $global:GithubRunURL"
  }

  #Send for report generation
  $reportID = Run-ASoC-GenerateReport ($global:scanId)
  
  #Check for report generation completion
  Run-ASoC-ReportCompletionChecker ($reportID)

  #Download report from ASoC and expose its filename to later steps (e.g. upload-artifact)
  $reportFile = Run-ASoC-DownloadReport($reportID)
  Set-GHOutput 'report_file' $reportFile

  #issues found in scan
  $jsonData = Run-ASoC-GetIssueCount $global:scanId 'None'

  #This prints the number of issues by Severity
  $env:ISSUE_COUNT_BY_SEV = $jsonData | Format-Table | Out-String
  Write-Host $env:ISSUE_COUNT_BY_SEV

  #Severity totals: expose as outputs and render in the job summary
  $sevCounts = Get-SeverityCounts($jsonData)
  $totalIssues = 0
  foreach($k in $sevCounts.Keys){ $totalIssues += $sevCounts[$k] }
  Set-GHOutput 'critical_count'      $sevCounts['Critical']
  Set-GHOutput 'high_count'          $sevCounts['High']
  Set-GHOutput 'medium_count'        $sevCounts['Medium']
  Set-GHOutput 'low_count'           $sevCounts['Low']
  Set-GHOutput 'informational_count' $sevCounts['Informational']
  Set-GHOutput 'total_issues'        $totalIssues

  Add-GHSummary "## :white_check_mark: Scan completed`n"
  Add-GHSeveritySummaryTable $sevCounts $totalIssues
  Add-GHTopIssuesTable $issueItems 20
  Add-GHSummary "The full HTML security report (``$reportFile``) is in the job workspace - attach it with ``actions/upload-artifact``.`n"

  $gateResult = 'passed'

  #Fail the build if fail_for_noncompliance is set to true and if scan result count exceeds the threshold set in fail_threshold
  if($env:INPUT_FAIL_FOR_NONCOMPLIANCE -eq $true){

    $jsonData = Run-ASoC-GetIssueCount $global:scanId 'All'
    #$jsonData
    
    $failBuild = $false
    $failBuild = FailBuild-ByNonCompliance($jsonData)
    if($failBuild -eq $true){
        $gateResult = 'failed'
        Set-GHOutput 'gate_result' $gateResult
        Write-GHError "Security gate failed: scan is non-compliant with the application policy configured on the AppScan server."
        Add-GHSummary "## :no_entry: Security gate: FAILED (policy non-compliance)`n"
        Add-GHSummary "The scan found issues violating the application policy set on the AppScan server. Review: $scanOverviewPage`n"
        Write-Error "Job failed - Scan has determined non-compliance with the application policy set in ASoC."
        exit 1
    }
    else{
        Write-Host "Job Successful - Scan has determined compliance with policy current application policies set in ASoC." -ForegroundColor Green
        Add-GHSummary "## :shield: Security gate: PASSED (policy compliance)`n"
    }
  }

  #Fail the build if fail_by_severity is true and scan results in non-compliance
  if($env:INPUT_FAIL_BY_SEVERITY -eq $true){
    $jsonData = Run-ASoC-GetIssueCount $global:scanId 'None'
    #$jsonData
    $failBuild = $false
    $failBuild = FailBuild-BySeverity $jsonData $env:INPUT_FAILURE_THRESHOLD
    Write-Debug "failbuild value is $failBuild"

    if($failBuild -eq $true){
        $gateResult = 'failed'
        Set-GHOutput 'gate_result' $gateResult
        Write-GHError "Security gate failed: issues found at or above severity threshold '$env:INPUT_FAILURE_THRESHOLD'. See the job summary for the breakdown."
        Add-GHSummary "## :no_entry: Security gate: FAILED`n"
        Add-GHSummary "Issues at or above **$env:INPUT_FAILURE_THRESHOLD** severity were found. The pipeline was failed by the ``fail_by_severity`` gate.`n"
        Write-Error "Job failed - Scan has found security issues equal to or above the threshold set: $env:INPUT_FAILURE_THRESHOLD"
        exit 1
    }
    else{
        Write-Host "Job Successful - Scan has found no issues equal to or above the threshold set: $env:INPUT_FAILURE_THRESHOLD." -ForegroundColor Green
        Add-GHSummary "## :shield: Security gate: PASSED`n"
        Add-GHSummary "No issues at or above **$env:INPUT_FAILURE_THRESHOLD** severity.`n"
    }
  }

  if(($env:INPUT_FAIL_FOR_NONCOMPLIANCE -ne $true) -and ($env:INPUT_FAIL_BY_SEVERITY -ne $true)){
    $gateResult = 'not_configured'
    Write-GHWarning "No security gate is configured (fail_by_severity and fail_for_noncompliance are both false). The job will pass regardless of findings."
    Add-GHSummary "## :warning: Security gate: not configured`n"
    Add-GHSummary "Enable ``fail_by_severity`` + ``failure_threshold`` (or ``fail_for_noncompliance``) to gate the pipeline on scan results.`n"
  }

  Set-GHOutput 'gate_result' $gateResult
}else{
  write-host "Since wait_for_analysis is set to false, the job is now complete. Exiting..."
  Set-GHOutput 'scan_status' 'Running'
  Set-GHOutput 'gate_result' 'not_evaluated'
  Write-GHNotice "wait_for_analysis=false: scan continues on the server. No results or gate are evaluated in this job. Track it here: $scanOverviewPage"
  Add-GHSummary "## :arrows_counterclockwise: Scan running asynchronously`n"
  Add-GHSummary "``wait_for_analysis`` is **false**, so this job only initiated the scan. Results and gates were **not** evaluated. Track progress: $scanOverviewPage`n"
  Exit 0
}
