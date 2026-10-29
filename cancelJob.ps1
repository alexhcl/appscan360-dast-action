# Copyright 2023-2026
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

#POST STEP - runs after ALL later workflow steps (including actions/upload-artifact):
#  1. If this job started a scan whose execution is still running (the workflow
#     was cancelled or died mid-scan), stop it on the AppScan server.
#  2. Append a "Downloads" section to the job summary with DIRECT artifact
#     download links (…/actions/runs/<run>/artifacts/<id>), which exist only
#     now that upload-artifact has published them.
#A failure in this step must never fail an otherwise green job.

$DebugPreference = "SilentlyContinue"

#INITIALIZE VARIABLES
$scanidFileName = ".\scanid.txt"
$ephemeralPresenceIdFileName =".\ephemeralPresenceId.txt"

$global:BaseAPIUrl = $env:INPUT_BASEURL + "/api/v4"

#LOAD ALL AppScan 360 FUNCTIONS FROM LIBRARY FILE asoc.ps1
. "$env:GITHUB_ACTION_PATH/asoc.ps1"

#---------------------------------------------------------------------------
#PART 1: stop a still-running scan execution (covers cancelled workflows).
#Monitor-mode runs never write scanid.txt and are skipped entirely.
#---------------------------------------------------------------------------
if(Test-Path $scanidFileName){
  $global:scanId = Get-Content $scanidFileName | Select-Object -First 1
  Write-Host "Post step - ScanID: $global:scanId"
  try{
    Login-ASoC -SoftFail

    $scanDetail = Run-ASoC-GetScanDetails($global:scanId)
    $progress = $scanDetail.LatestExecution.ExecutionProgress
    if($progress -ne 'Completed'){
      Write-Host "Scan execution is still '$progress' - the workflow ended early; stopping it on the server."
      Write-GHWarning "Workflow ended before the scan completed - stopping the running execution (scan $global:scanId) on the AppScan server."
      Add-GHSummary "## :grey_exclamation: Scan stopped`n"
      Add-GHSummary "The workflow ended before the scan finished, so the running execution of scan ``$global:scanId`` was stopped on the AppScan server.`n"
      Delete-LatestRunningScanExecution($global:scanId)

      # kill the ephemeral presence if one was set
      if(($env:INPUT_EPHEMERAL_PRESENCE -eq $true) -and (Test-Path $ephemeralPresenceIdFileName)){
        $global:ephemeralPresenceId = Get-Content $ephemeralPresenceIdFileName | Select-Object -First 1
        Write-Host "Deleting ephemeral presence with ID: $global:ephemeralPresenceId"
        Run-ASoC-DeletePresence($global:ephemeralPresenceId)
      }
    } else {
      Write-Host "Scan execution already completed - nothing to stop."
    }
  }catch{
    Write-Host "Post-step scan check skipped: $($_.Exception.Message)"
  }
}else{
  Write-Host "No scan was started by this job (monitor mode or pre-scan failure) - nothing to stop."
}

#---------------------------------------------------------------------------
#PART 2: direct artifact download links in the job summary.
#upload-artifact has already run by the time post steps execute, so the
#GitHub API now knows the artifact ids that direct links require.
#---------------------------------------------------------------------------
if(-not [string]::IsNullOrEmpty($env:INPUT_GITHUB_TOKEN)){
  try{
    $uri = "$env:GITHUB_API_URL/repos/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID/artifacts?per_page=50"
    $resp = Invoke-RestMethod -Uri $uri -Headers @{
      Authorization          = "Bearer $env:INPUT_GITHUB_TOKEN"
      Accept                 = 'application/vnd.github+json'
      'X-GitHub-Api-Version' = '2022-11-28'
    }
    $arts = @($resp.artifacts | Where-Object { -not $_.expired })
    if($arts.Count -gt 0){
      Add-GHSummary "## :inbox_tray: Downloads`n"
      Add-GHSummary "| Artifact | Size | Direct download |"
      Add-GHSummary "|---|---|---|"
      foreach($a in $arts){
        $dl = "$env:GITHUB_SERVER_URL/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID/artifacts/$($a.id)"
        $mb = [math]::Round($a.size_in_bytes/1MB, 2)
        Add-GHSummary ("| {0} | {1} MB | [Download zip]({2}) |" -f $a.name, $mb, $dl)
      }
      Add-GHSummary ""
      Write-Host ("Appended direct download link(s) for {0} artifact(s) to the job summary." -f $arts.Count)
    } else {
      Write-Host "This run has no (unexpired) artifacts - no download links to append."
    }
  }catch{
    Write-Host "Could not list run artifacts for direct download links: $($_.Exception.Message)"
    Write-Host "The github_token needs 'actions: read' permission on this repository."
  }
}else{
  Write-Host "github_token input is empty - skipping the Downloads section."
}
