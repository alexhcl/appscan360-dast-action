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

$Os = 'linux'
if($IsMacOS){
  $Os = 'mac'
}elseif($IsWindows){
  $Os = 'win'
}

$ClientType = "github-dast-$Os-$env:GITHUB_ACTION_REF"

# Handle SSL validation.
# TLS certificate verification is SKIPPED BY DEFAULT: self-managed AppScan 360
# servers commonly present a certificate whose CA is not in the runner's trust
# store, and requiring it per runner was the most frequent cause of failures.
# Set ACCEPTSSL: "false" (env on the step) to ENFORCE strict TLS verification
# once the server CA is trusted on the runner - recommended for production,
# since skipping verification exposes the API key to interception.
$global:SkipCert = $true

if ($env:ACCEPTSSL -eq "false") {
    $global:SkipCert = $false
}

# =================================
# Base API URL
# =================================

$global:BaseAPIUrl = "$env:INPUT_BASEURL/api/v4"
Write-Host "Using AppScan Base API URL: $global:BaseAPIUrl"


Write-Host "Loading Library functions from asoc.ps1"

#Load GitHub Actions helper functions (job summary, outputs, annotations)
. "$env:GITHUB_ACTION_PATH/github.ps1"

function Invoke-PostScanCommand {
  #Runs post_scan_command (if set) with whatever ASOC_* context the caller has
  #already exported. Shared by the sync path (full results) and the async path
  #(IDs/URL only). A failing command only warns - it never changes the gate.
  if([string]::IsNullOrEmpty($env:INPUT_POST_SCAN_COMMAND)){ return }
  Write-Host "Running post_scan_command..."
  $global:LASTEXITCODE = 0
  try{
    Invoke-Expression $env:INPUT_POST_SCAN_COMMAND
    if(($null -ne $LASTEXITCODE) -and ($LASTEXITCODE -ne 0)){
      Write-GHWarning "post_scan_command exited with code $LASTEXITCODE. The scan result and gate verdict are unaffected."
      Add-GHSummary "## :warning: Post-scan command exited with code $LASTEXITCODE`n"
    } else {
      Write-Host "post_scan_command completed." -ForegroundColor Green
      Add-GHSummary "## :outbox_tray: Post-scan command executed`n"
    }
  }catch{
    Write-GHWarning "post_scan_command failed: $($_.Exception.Message). The scan result and gate verdict are unaffected."
    Add-GHSummary "## :warning: Post-scan command failed: $($_.Exception.Message)`n"
  }
}

#FUNCTIONS
function Login-ASoC {
  param([switch]$SoftFail)

  $jsonBody = @{
    KeyId         = $env:INPUT_ASOC_KEY
    KeySecret     = $env:INPUT_ASOC_SECRET
  }

  $params = @{
      Uri         = "$global:BaseAPIUrl/Account/ApiKeyLogin"
      Method      = 'POST'
      Body        = $jsonBody | ConvertTo-Json
      Headers = @{
          'Content-Type' = 'application/json'
          'accept' = 'application/json'
          'ClientType' = "$ClientType"
        }
      }
  #DEBUG
  Write-Debug ($jsonBody | Format-Table | Out-String)
  Write-Debug ($params | Format-Table | Out-String)


  #$Members = Invoke-RestMethod @params
  try{
    if ($global:SkipCert) {
      $Members = Invoke-RestMethod @params -SkipCertificateCheck
    } else {
      $Members = Invoke-RestMethod @params
    }
  }catch{
    #Surface the REAL reason (TLS trust, DNS, refused, 4xx body) instead of a
    #truncated "Invoke-RestMethod: line NN" in the run log
    $msg = $_.Exception.Message
    if($_.Exception.InnerException){ $msg += " | inner: " + $_.Exception.InnerException.Message }
    Write-GHError "Login to $global:BaseAPIUrl failed: $msg"
    Write-Host "Login to $global:BaseAPIUrl failed: $msg"
    Write-Host "Hints: UntrustedRoot/SSL = import the CA into Cert:\LocalMachine\Root on THIS runner (user-store imports do not apply to service accounts); 'No such host' = hosts/DNS entry missing; 400 KeyId = credential inputs empty."
    if($SoftFail){ throw $msg }
    exit 1
  }
  Write-Debug ($Members | Format-Table | Out-String)

  #Write-Host "Auth successful - Token received: $Members.token"
  $global:BearerToken = $Members.token

  if($global:BearerToken -ne ""){
    Write-Host "Login successful"
  }else{
    if($SoftFail){ throw "Login returned no token" }
    Write-Error "Login failed... exiting"
    exit 1
  }
  
}

function Set-AppScanPresence{

  if($env:INPUT_NETWORK -eq 'private'){
    
    $global:jsonBodyInPSObject.Add("PresenceId",$env:INPUT_PRESENCE_ID)
<# 
    $global:jsonBodyInPSObject =+ @{
      PresenceId = $env:INPUT_PRESENCE_ID
    } #> 
  }
}

function Lookup-ASoC-Application ($ApplicationName) {

  $params = @{
      Uri         = "$env:INPUT_BASEURL/Apps"
      Method      = 'GET'
      Headers = @{
          'Content-Type' = 'application/json'
          Authorization = "Bearer $global:BearerToken"
        }
      }
  #$Members = Invoke-RestMethod @params
  if ($global:SkipCert) {
    $Members = Invoke-RestMethod @params -SkipCertificateCheck
  } else {
    $Members = Invoke-RestMethod @params
  }
  Write-Host @Members
  $Members.Items.Contains($ApplicationName)
}


function Run-ASoC-FileUpload($filepath){

  #ls -l
  $uploadedFile = [IO.File]::ReadAllBytes($filepath)
  $params = @{
    Uri         = "$global:BaseAPIUrl/FileUpload"
    Method      = 'Post'
    Headers = @{
      'Content-Type' = 'multipart/form-data'
      Authorization = "Bearer $global:BearerToken"
    }
     Form = @{
    'uploadedFile' = Get-Item -Path $filepath
   }
  }
  #$upload = Invoke-RestMethod @params
  if ($global:SkipCert) {
     $upload = Invoke-RestMethod @params -SkipCertificateCheck
  } else {
     $upload = Invoke-RestMethod @params
  }
  $upload_File_ID = $upload.FileId
  write-host "File Uploaded - File ID: $upload_File_ID"

  return $upload_File_ID
}
function Run-ASoC-DynamicAnalyzerNoAuth {
  Write-Host "Proceeding with no authentications..." -ForegroundColor Green

  return Run-ASoC-DynamicAnalyzerAPI($global:jsonBodyInPSObject | ConvertTo-Json)
}
function Run-ASoC-DynamicAnalyzerUserPass{
  Write-Host "Proceeding with username and password login..." -ForegroundColor Green

  $Login = @{
     'Username' = $env:INPUT_LOGIN_USER
     'Password' = $env:INPUT_LOGIN_PASSWORD
  }
  $global:jsonBodyInPSObject.ScanConfiguration.Add('Login', $Login)

  return Run-ASoC-DynamicAnalyzerAPI($jsonBodyInPSObject | ConvertTo-Json)
}

function Run-ASoC-DynamicAnalyzerRecordedLogin{

  Write-Host "Proceeding with recorded Login..." -ForegroundColor Green
  #Upload Recorded Login File
  $FileID = Run-ASoC-FileUpload($env:INPUT_LOGIN_SEQUENCE_FILE)
  $global:jsonBodyInPSObject.Add("LoginSequenceFileId",$FileID)
  return Run-ASoC-DynamicAnalyzerAPI($jsonBodyInPSObject | ConvertTo-Json)
}


function Run-ASoC-DynamicAnalyzerWithFile{

  $FileID = Run-ASoC-FileUpload($env:INPUT_SCAN_OR_SCANT_FILE)
  $global:jsonBodyInPSObject.Remove('ScanConfiguration')
  $global:jsonBodyInPSObject.Add("ScanOrTemplateFileId",$FileID)

  #Test operation for uploaded scan files:
  #  FullScan  - continue the Explore stage (adds to explore data in the file), then Test (server default)
  #  TestOnly  - run ONLY the Test stage on the explore data already in the file (Manual Explore / MSO)
  #  ReportOnly- import the file's results without running a scan
  if(-not [string]::IsNullOrEmpty($env:INPUT_SCAN_TYPE)){
    $global:jsonBodyInPSObject.Add("TestOperation",$env:INPUT_SCAN_TYPE)
    Write-Host "Scan type (TestOperation): $env:INPUT_SCAN_TYPE"
  }

  return Run-ASoC-DynamicAnalyzerAPI($jsonBodyInPSObject | ConvertTo-Json)
}

function Run-ASoC-DynamicAnalyzerAPI($json){

  write-host $json
  $params = @{
    Uri         = "$global:BaseAPIUrl/Scans/Dast"
    Method      = 'POST'
    Body        = $json
    Headers = @{
        'Content-Type' = 'application/json'
        'ClientType' = "$ClientType"
        Authorization = "Bearer $global:BearerToken"
      }
    }

  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)
  
  #$Members = Invoke-RestMethod @params
  try{
    if ($global:SkipCert) {
      $Members = Invoke-RestMethod @params -SkipCertificateCheck
    } else {
      $Members = Invoke-RestMethod @params
    }
  }catch{
    #Surface the server's actual rejection (response body) instead of a
    #truncated "Invoke-RestMethod: line NN"
    $detail = $_.ErrorDetails.Message
    if([string]::IsNullOrEmpty($detail)){ $detail = $_.Exception.Message }
    Write-GHError "Scan creation failed (POST /Scans/Dast): $detail"
    Write-Host "Scan creation failed (POST /Scans/Dast): $detail"
    Write-Host "Common causes: the target domain is not verified for this application (verify it in the AppScan 360 portal under the app's domains), a Presence is required for an internal/unreachable target (network: private + presence_id), or a scan/licence limit was reached."
    exit 1
  }
  return $Members.Id
}

function Run-ASoC-GetScansForApp($appId){

  #Fetch all scans of an application (used by rescan_latest resolution and monitor mode)
  $params = @{
    Uri         = "$global:BaseAPIUrl/Scans"+"?%24filter=AppId%20eq%20"+$appId
    Method      = 'GET'
    Headers = @{
      'Content-Type' = 'application/json'
      Authorization = "Bearer $global:BearerToken"
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  if ($global:SkipCert) {
	$response = Invoke-RestMethod @params -SkipCertificateCheck
  } else {
	$response = Invoke-RestMethod @params
  }
  return $response.Items
}

function Select-MonitorScans($scans){

  #Apply the monitor filters (pure function - also exercised by smoke tests):
  #  MONITOR_SCAN_ID       : exact scan ID
  #  MONITOR_NAME_CONTAINS : case-insensitive substring of the scan name
  #  MONITOR_FROM_DATE / MONITOR_TO_DATE : CreatedAt range, inclusive (yyyy-MM-dd)
  if($null -eq $scans){ return @() }
  $result = @($scans)

  if(-not [string]::IsNullOrEmpty($env:INPUT_MONITOR_SCAN_ID)){
    $result = @($result | Where-Object { "$($_.Id)" -eq $env:INPUT_MONITOR_SCAN_ID })
  }

  if(-not [string]::IsNullOrEmpty($env:INPUT_MONITOR_NAME_CONTAINS)){
    $needle = $env:INPUT_MONITOR_NAME_CONTAINS
    $result = @($result | Where-Object { ("$($_.Name)").IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 })
  }

  if(-not [string]::IsNullOrEmpty($env:INPUT_MONITOR_FROM_DATE)){
    try{
      $from = [datetime]::Parse($env:INPUT_MONITOR_FROM_DATE)
      $result = @($result | Where-Object { ($null -ne $_.CreatedAt) -and ([datetime]::Parse("$($_.CreatedAt)") -ge $from) })
    }catch{ Write-GHWarning "monitor_from_date '$env:INPUT_MONITOR_FROM_DATE' could not be parsed (use yyyy-MM-dd) - filter skipped." }
  }

  if(-not [string]::IsNullOrEmpty($env:INPUT_MONITOR_TO_DATE)){
    try{
      $to = [datetime]::Parse($env:INPUT_MONITOR_TO_DATE).AddDays(1)   #inclusive end date
      $result = @($result | Where-Object { ($null -ne $_.CreatedAt) -and ([datetime]::Parse("$($_.CreatedAt)") -lt $to) })
    }catch{ Write-GHWarning "monitor_to_date '$env:INPUT_MONITOR_TO_DATE' could not be parsed (use yyyy-MM-dd) - filter skipped." }
  }

  #Newest first when dates are available
  $withDates = @($result | Where-Object { $null -ne $_.PSObject.Properties['CreatedAt'] -and $null -ne $_.CreatedAt })
  if($withDates.Count -eq $result.Count -and $result.Count -gt 0){
    $result = @($result | Sort-Object -Property CreatedAt -Descending)
  }
  return $result
}

function Add-ScanHistorySection{

  #SCAN HISTORY: a compact, links-only section appended to the job summary of
  #every normal run (scan_history, default true). One extra GET, no report
  #generation - the heavyweight browsing stays in monitor mode.
  $limit = 15
  if(-not [string]::IsNullOrEmpty($env:INPUT_SCAN_HISTORY_LIMIT)){
    try{ $limit = [int]$env:INPUT_SCAN_HISTORY_LIMIT }catch{}
  }
  if($limit -le 0){ return }

  try{
    $allScans = Run-ASoC-GetScansForApp($env:INPUT_APPLICATION_ID)
  }catch{
    Write-GHWarning "Scan history could not be fetched: $($_.Exception.Message)"
    return
  }
  if($null -eq $allScans -or @($allScans).Count -eq 0){ return }
  $scans = @($allScans)

  #Newest first when dates are available
  $withDates = @($scans | Where-Object { $null -ne $_.PSObject.Properties['CreatedAt'] -and $null -ne $_.CreatedAt })
  if($withDates.Count -eq $scans.Count){
    $scans = @($scans | Sort-Object -Property CreatedAt -Descending)
  }
  $total = $scans.Count
  $shown = @($scans | Select-Object -First $limit)

  Add-GHSummary "## :clock3: Scan history`n"
  Add-GHSummary "| Created | Scan name | Scan ID | Status | Open scan |"
  Add-GHSummary "|---|---|---|---|---|"
  foreach($s in $shown){
    $created = "$($s.CreatedAt)"
    if($created.Length -ge 10){ $created = $created.Substring(0,10) }
    $status = ''
    if($null -ne $s.PSObject.Properties['LatestExecution'] -and $null -ne $s.LatestExecution){ $status = $s.LatestExecution.Status }
    $marker = ''
    if("$($s.Id)" -eq "$global:scanId"){ $marker = ' **(this run)**' }
    $openUrl = $env:INPUT_BASEURL + "/main/myapps/" + $env:INPUT_APPLICATION_ID + "/scans/" + $s.Id
    Add-GHSummary ("| {0} | {1}{2} | ``{3}`` | {4} | [Open scan]({5}) |" -f $created, $s.Name, $marker, $s.Id, $status, $openUrl)
  }
  if($total -gt $shown.Count){
    Add-GHSummary ("`n_Showing the {0} most recent of {1} scans. Use monitor mode (``monitor: true``) to filter further and download reports._`n" -f $shown.Count, $total)
  } else {
    Add-GHSummary ""
  }
}

function Run-ASoC-MonitorScans{

  #MONITOR MODE: list past scans of the application, filtered, with per-scan
  #links (open in portal) and downloaded HTML reports (run artifacts).
  $maxReports = 10
  if(-not [string]::IsNullOrEmpty($env:INPUT_MONITOR_MAX_REPORTS)){
    try{ $maxReports = [int]$env:INPUT_MONITOR_MAX_REPORTS }catch{}
  }

  Write-Host "MONITOR MODE: listing scans for application $env:INPUT_APPLICATION_ID"
  $allScans = Run-ASoC-GetScansForApp($env:INPUT_APPLICATION_ID)
  $matched = Select-MonitorScans $allScans
  $totalOnServer = 0
  if($null -ne $allScans){ $totalOnServer = @($allScans).Count }
  Write-Host ("Scans on server for this application: {0} | matching filters: {1}" -f $totalOnServer, $matched.Count)

  Set-GHOutput 'monitor_matches' $matched.Count

  #Summary header with the active filters
  Add-GHSummary "# AppScan 360 scan monitor`n"
  Add-GHSummary "| | |"
  Add-GHSummary "|---|---|"
  Add-GHSummary "| **Application** | ``$env:INPUT_APPLICATION_ID`` |"
  if(-not [string]::IsNullOrEmpty($env:INPUT_MONITOR_SCAN_ID)){       Add-GHSummary "| **Filter: scan ID** | ``$env:INPUT_MONITOR_SCAN_ID`` |" }
  if(-not [string]::IsNullOrEmpty($env:INPUT_MONITOR_NAME_CONTAINS)){ Add-GHSummary "| **Filter: name contains** | ``$env:INPUT_MONITOR_NAME_CONTAINS`` |" }
  if(-not [string]::IsNullOrEmpty($env:INPUT_MONITOR_FROM_DATE)){     Add-GHSummary "| **Filter: from** | $env:INPUT_MONITOR_FROM_DATE |" }
  if(-not [string]::IsNullOrEmpty($env:INPUT_MONITOR_TO_DATE)){       Add-GHSummary "| **Filter: to** | $env:INPUT_MONITOR_TO_DATE |" }
  Add-GHSummary "| **Matches** | **$($matched.Count)** of $totalOnServer scans |`n"

  if($matched.Count -eq 0){
    Add-GHSummary "_No scans matched the filters._`n"
    Write-GHNotice "Monitor: no scans matched the filters."
    return
  }

  #Reports. By default one HTML report per matched scan (the scan's latest
  #execution). With monitor_report_per_execution=true, one report per EXECUTION
  #instead - generated in the Executions section below. Either way files share
  #the AppScan_Monitor_Report- prefix so one upload-artifact glob catches them,
  #and monitor_max_reports caps the TOTAL number downloaded.
  $perExec = ($env:INPUT_MONITOR_REPORT_PER_EXECUTION -eq $true)
  $reportFiles = @()
  $reportByScanId = @{}
  $reportByExecId = @{}
  if(-not $perExec){
    $i = 0
    foreach($s in $matched){
      if($reportFiles.Count -ge $maxReports){ break }
      $i++
      Write-Host ("[{0}/{1}] Generating report for scan '{2}' ({3})..." -f $i, [Math]::Min($matched.Count,$maxReports), $s.Name, $s.Id)
      try{
        $repId = Run-ASoC-GenerateReport($s.Id)
        Run-ASoC-ReportCompletionChecker($repId)
        $safeName = ("$($s.Name)" -replace '[^A-Za-z0-9._-]','_')
        if($safeName.Length -gt 60){ $safeName = $safeName.Substring(0,60) }
        $fileName = "AppScan_Monitor_Report-$safeName-$($s.Id).html"
        $saved = Run-ASoC-DownloadReport $repId $fileName
        $reportFiles += $saved
        $reportByScanId["$($s.Id)"] = $saved
      }catch{
        Write-GHWarning "Monitor: report for scan $($s.Id) could not be generated: $($_.Exception.Message)"
        $reportByScanId["$($s.Id)"] = ''
      }
    }
  } else {
    Write-Host "monitor_report_per_execution=true - a report will be generated per execution (see the Executions section); monitor_max_reports caps the total."
  }

  #Render the scans table. Report links jump to this run's Artifacts section,
  #where the uploaded zip with the reports lives (GitHub has no per-file URLs).
  $artifactsUrl = "$env:GITHUB_SERVER_URL/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID#artifacts"
  Add-GHSummary "### Scans`n"
  Add-GHSummary "| Created | Scan name | Scan ID | Status | Open scan | Report |"
  Add-GHSummary "|---|---|---|---|---|---|"
  foreach($s in $matched){
    $created = "$($s.CreatedAt)"
    if($created.Length -ge 10){ $created = $created.Substring(0,10) }
    $status = ''
    if($null -ne $s.PSObject.Properties['LatestExecution'] -and $null -ne $s.LatestExecution){ $status = $s.LatestExecution.Status }
    $openUrl = $env:INPUT_BASEURL + "/main/myapps/" + $env:INPUT_APPLICATION_ID + "/scans/" + $s.Id
    $reportCell = "-"
    if($perExec){
      $reportCell = "per execution (see below)"
    } elseif($reportByScanId.ContainsKey("$($s.Id)") -and -not [string]::IsNullOrEmpty($reportByScanId["$($s.Id)"])){
      $reportCell = "[``$($reportByScanId["$($s.Id)"])``]($artifactsUrl)"
    } elseif($reportFiles.Count -ge $maxReports) {
      $reportCell = "not downloaded (over monitor_max_reports)"
    }
    Add-GHSummary ("| {0} | {1} | ``{2}`` | {3} | [Open scan]({4}) | {5} |" -f $created, $s.Name, $s.Id, $status, $openUrl, $reportCell)
  }
  Add-GHSummary ""

  #Executions per matched scan. The list is capped to the most recent scans to
  #keep API churn sane. With monitor_report_per_execution=true, this section
  #also generates + downloads a report for each execution (capped by
  #monitor_max_reports across all scans) and links it in a Report column.
  if(($env:INPUT_MONITOR_SHOW_EXECUTIONS -ne $false) -or $perExec){
    $execScanCap = 10
    $shownScans = @($matched | Select-Object -First $execScanCap)
    Add-GHSummary "### Executions`n"
    if($perExec){
      Add-GHSummary "| Scan | Execution ID | Created | Status | Report |"
      Add-GHSummary "|---|---|---|---|---|"
    } else {
      Add-GHSummary "| Scan | Execution ID | Created | Status |"
      Add-GHSummary "|---|---|---|---|"
    }
    $execRows = 0
    foreach($s in $shownScans){
      try{
        $execs = Run-ASoC-GetScanExecutions($s.Id)
      }catch{
        Write-GHWarning "Monitor: executions for scan $($s.Id) could not be fetched: $($_.Exception.Message)"
        continue
      }
      $withDates = @($execs | Where-Object { $null -ne $_.PSObject.Properties['CreatedAt'] -and $null -ne $_.CreatedAt })
      if($withDates.Count -eq @($execs).Count -and @($execs).Count -gt 0){
        $execs = @($execs | Sort-Object -Property CreatedAt -Descending)
      }
      foreach($e in $execs){
        $ecreated = "$($e.CreatedAt)"
        if($ecreated.Length -ge 16){ $ecreated = $ecreated.Substring(0,16).Replace("T"," ") }
        if($perExec){
          $reportCell = "-"
          if($reportFiles.Count -ge $maxReports){
            $reportCell = "not downloaded (over monitor_max_reports)"
          } else {
            try{
              Write-Host ("Generating report for execution {0} (scan '{1}')..." -f $e.Id, $s.Name)
              $repId = Run-ASoC-GenerateReportForExecution($e.Id)
              Run-ASoC-ReportCompletionChecker($repId)
              $safeName = ("$($s.Name)" -replace '[^A-Za-z0-9._-]','_')
              if($safeName.Length -gt 50){ $safeName = $safeName.Substring(0,50) }
              $fileName = "AppScan_Monitor_Report-$safeName-exec-$($e.Id).html"
              $saved = Run-ASoC-DownloadReport $repId $fileName
              $reportFiles += $saved
              $reportByExecId["$($e.Id)"] = $saved
              $reportCell = "[``$saved``]($artifactsUrl)"
            }catch{
              Write-GHWarning "Monitor: report for execution $($e.Id) could not be generated: $($_.Exception.Message)"
            }
          }
          Add-GHSummary ("| {0} | ``{1}`` | {2} | {3} | {4} |" -f $s.Name, $e.Id, $ecreated, $e.Status, $reportCell)
        } else {
          Add-GHSummary ("| {0} | ``{1}`` | {2} | {3} |" -f $s.Name, $e.Id, $ecreated, $e.Status)
        }
        $execRows++
      }
    }
    if($execRows -eq 0){
      if($perExec){ Add-GHSummary "| _no executions_ | | | | |" } else { Add-GHSummary "| _no executions_ | | | |" }
    }
    if($matched.Count -gt $execScanCap){
      Add-GHSummary ("`n_Executions shown for the {0} most recent scans of {1} matched._" -f $execScanCap, $matched.Count)
    }
    Add-GHSummary ""
  }

  Set-GHOutput 'monitor_report_files' ($reportFiles -join ' ')
  # Also expose the filenames as a JSON array, so a workflow matrix can publish
  # each report as its own artifact without parsing strings in shell.
  $reportsJson = if($reportFiles.Count -gt 0){ (@($reportFiles) | ConvertTo-Json -Compress -AsArray) } else { '[]' }
  Set-GHOutput 'monitor_report_files_json' $reportsJson

  if($reportFiles.Count -gt 0){
    Add-GHSummary ("{0} HTML report(s) downloaded. Direct download links appear in the **Downloads** section at the bottom of this summary once the ``actions/upload-artifact`` step has published them.`n" -f $reportFiles.Count)
  }
  Write-GHNotice ("Monitor: {0} scan(s) matched; {1} report(s) downloaded." -f $matched.Count, $reportFiles.Count)
}

function Run-ASoC-GetLatestScanIdForApp($appId){

  #Look up the most recent DAST scan of an application. Used by scan_id: 'latest'.
  #Sorting is done client-side for robustness across server versions.
  $params = @{
    Uri         = "$global:BaseAPIUrl/Scans"+"?%24filter=AppId%20eq%20"+$appId
    Method      = 'GET'
    Headers = @{
      'Content-Type' = 'application/json'
      Authorization = "Bearer $global:BearerToken"
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  if ($global:SkipCert) {
	$response = Invoke-RestMethod @params -SkipCertificateCheck
  } else {
	$response = Invoke-RestMethod @params
  }
  $scans = $response.Items
  if($null -eq $scans -or $scans.Count -eq 0){ return '' }

  #Prefer DAST scans if the Technology property is present (skip SAST/SCA scans of the same app)
  $dastScans = @($scans | Where-Object { ($null -eq $_.PSObject.Properties['Technology']) -or ($_.Technology -eq 'DynamicAnalyzer') })
  if($dastScans.Count -eq 0){ $dastScans = @($scans) }

  #Newest first by CreatedAt when available, else keep server order and take the last
  $withDates = @($dastScans | Where-Object { $null -ne $_.PSObject.Properties['CreatedAt'] })
  if($withDates.Count -gt 0){
    $latest = $withDates | Sort-Object -Property CreatedAt -Descending | Select-Object -First 1
  } else {
    $latest = $dastScans[-1]
  }
  Write-Host ("Latest scan for application {0}: '{1}' (ID: {2}, created {3})" -f $appId, $latest.Name, $latest.Id, $latest.CreatedAt)
  return $latest.Id
}

function Run-ASoC-SetScanMailNotification($scanId, $enabled){

  #Best-effort: set the scan's EnableMailNotifications flag so RESCANS honor the
  #email_notification input (the per-execution API has no mail flag - it is a
  #property of the scan). Uses PUT /Scans/{id} (UpdateScanWithPresenceAndRecurrence,
  #field 'EnableMailNotifications', plural). A server that declines only warns.
  $params = @{
    Uri         = "$global:BaseAPIUrl/Scans/$scanId"
    Method      = 'PUT'
    Headers = @{
      'Content-Type' = 'application/json'
      Authorization = "Bearer $global:BearerToken"
    }
  }
  $body = @{ EnableMailNotifications = [bool]$enabled }
  try{
    if ($global:SkipCert) {
      Invoke-RestMethod @params -Body ($body|ConvertTo-Json) -SkipCertificateCheck | Out-Null
    } else {
      Invoke-RestMethod @params -Body ($body|ConvertTo-Json) | Out-Null
    }
    Write-Host ("Email notification for rescan set to: {0}" -f $enabled)
    return $true
  }catch{
    Write-GHWarning "email_notification: the server declined updating mail notification on scan $scanId ($($_.Exception.Message)). The rescan keeps the scan's stored setting."
    return $false
  }
}

function Run-ASoC-RenameScan($scanId, $newName){

  #Best-effort rename so rescans honor scan_name (an execution otherwise
  #keeps the scan's stored name). A server that declines only warns.
  $params = @{
    Uri         = "$global:BaseAPIUrl/Scans/$scanId"
    Method      = 'PUT'
    Headers = @{
      'Content-Type' = 'application/json'
      Authorization = "Bearer $global:BearerToken"
    }
  }
  $body = @{ Name = $newName }
  try{
    if ($global:SkipCert) {
      Invoke-RestMethod @params -Body ($body|ConvertTo-Json) -SkipCertificateCheck | Out-Null
    } else {
      Invoke-RestMethod @params -Body ($body|ConvertTo-Json) | Out-Null
    }
    Write-Host "Scan renamed to: $newName"
    return $true
  }catch{
    Write-GHWarning "scan_name: the server declined renaming scan $scanId to '$newName' ($($_.Exception.Message)). The execution keeps the scan's stored name."
    return $false
  }
}

function Run-ASoC-GetScanExecutions($scanId){

  #All executions of a scan, for the monitor Executions table
  $params = @{
    Uri         = "$global:BaseAPIUrl/Scans/$scanId/Executions"
    Method      = 'GET'
    Headers = @{
      'Content-Type' = 'application/json'
      Authorization = "Bearer $global:BearerToken"
    }
  }
  if ($global:SkipCert) {
	$out = Invoke-RestMethod @params -SkipCertificateCheck
  } else {
	$out = Invoke-RestMethod @params
  }
  if($null -eq $out){ return @() }
  if($out -is [array]){ return $out }
  if($null -ne $out.PSObject.Properties['Items']){ return @($out.Items) }
  return @($out)
}

function Run-ASoC-Rescan($scanId){

  #Trigger a new execution of an EXISTING scan (rescan). The scan's stored
  #configuration, target and login macro on the server are reused; the
  #action's file/login inputs are ignored in this mode.
  $params = @{
    Uri         = "$global:BaseAPIUrl/Scans/$scanId/Executions"
    Method      = 'POST'
    Headers = @{
      'Content-Type' = 'application/json'
      Authorization = "Bearer $global:BearerToken"
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  $body = @{}
  if ($global:SkipCert) {
	$output = Invoke-RestMethod @params -Body ($body|ConvertTo-Json) -SkipCertificateCheck
  } else {
	$output = Invoke-RestMethod @params -Body ($body|ConvertTo-Json)
  }
  return $output.Id
}

function Run-ASoC-DAST{

  #FIRST check if dynamic_scan_type is 'upload' or 'dast'
  if($env:INPUT_DYNAMIC_SCAN_TYPE -eq 'upload'){
    return Run-ASoC-DynamicAnalyzerWithFile
  
  #If dynamic_scan_type is not 'upload' then it is a regular 'dast' scan. We proceed to check if it's a userpass login or recorded login
  }elseif($env:INPUT_LOGIN_METHOD -eq 'userpass'){
    return Run-ASoC-DynamicAnalyzerUserPass

  }elseif($env:INPUT_LOGIN_METHOD -eq 'recorded'){
    return Run-ASoC-DynamicAnalyzerRecordedLogin

  }else{
    return Run-ASoC-DynamicAnalyzerNoAuth
  }
}

function Run-ASoC-ScanCompletionChecker($scanID){
  $params = @{
    Uri         = "$global:BaseAPIUrl/Scans/$scanID/Executions"
    Method      = 'GET'
    Headers = @{
      'Content-Type' = 'application/json'
      Authorization = "Bearer $global:BearerToken"
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  $counterTimerInSeconds = 0
  Write-Host "Waiting for Scan Completion..."
  $waitIntervalInSeconds = 15
  $statusLineEverySeconds = 300   #print a timestamped status line every 5 minutes
  $pausedWarned = $false
  $scanOverviewPage = $env:INPUT_BASEURL + "/main/myapps/" + $env:INPUT_APPLICATION_ID + "/scans/" + $global:scanId

  while(($scan_status -ne "Ready") -and ($counterTimerInSeconds -lt $env:INPUT_WAIT_FOR_ANALYSIS_TIMEOUT_MINUTES*60)){
    #$output = Invoke-RestMethod @params
	if ($global:SkipCert) {
		$output = Invoke-RestMethod @params -SkipCertificateCheck
	} else {
		$output = Invoke-RestMethod @params
	}
	#The Executions endpoint returns all executions of the scan. On a rescan
	#there are several: track the one THIS job started (else the most recent),
	#so an old Failed execution can never fail or complete this job by mistake.
	$exec = $output
	if($output -is [array]){
	  $exec = $null
	  if(-not [string]::IsNullOrEmpty($global:executionId)){
	    $exec = $output | Where-Object { $_.Id -eq $global:executionId } | Select-Object -First 1
	  }
	  if($null -eq $exec){
	    $sorted = $output | Sort-Object -Property CreatedAt -Descending
	    if($sorted){ $exec = $sorted | Select-Object -First 1 } else { $exec = $output[-1] }
	  }
	}
	$scan_status = $exec.Status
    Start-Sleep -Seconds $waitIntervalInSeconds
    $counterTimerInSeconds = $counterTimerInSeconds + $waitIntervalInSeconds
    Write-Host "." -NoNewline

    #Periodic visible progress: status + progress + elapsed time
    if(($counterTimerInSeconds % $statusLineEverySeconds) -lt $waitIntervalInSeconds){
      $elapsedMin = [math]::Floor($counterTimerInSeconds / 60)
      #Some server builds report Progress as a value other than 0-100;
      #only display it as a percentage when it plausibly is one
      $progressText = ''
      $progressRaw = $exec.Progress
      if($null -ne $progressRaw -and "$progressRaw" -match '^\d{1,3}$' -and [int]$progressRaw -le 100){
        $progressText = " | Progress: $progressRaw%"
      }
      Write-Host ""
      Write-Host ("[{0}] Scan status: {1}{2} | Elapsed: {3} min" -f (Get-Date -Format "HH:mm:ss"), $scan_status, $progressText, $elapsedMin)
    }

    #Terminal failure states: surface loudly and fail the job immediately
    if(($scan_status -eq 'Failed') -or ($scan_status -eq 'Stopped')){
      $error_message = $exec.UserMessage
      Write-Host ""
      Set-GHOutput 'scan_status' $scan_status
      Set-GHOutput 'gate_result' 'error'
      Write-GHError "DAST scan ended with status '$scan_status'. Message: $error_message. Execution log: $scanOverviewPage"
      Add-GHSummary "## :x: AppScan DAST scan $scan_status`n"
      Add-GHSummary "**Scan ID:** ``$global:scanId``  "
      Add-GHSummary "**Server message:** $error_message  "
      Add-GHSummary "**Execution log:** $scanOverviewPage`n"
      Write-Error "Scan status: $scan_status. Scan UserMessage: $error_message. For More detail, see Execution log available at your scan view: $scanOverviewPage"
      Exit 1
    }

    #Paused scans (e.g. waiting for manual intervention) - warn once, keep waiting until timeout
    if(($scan_status -eq 'Paused') -and (-not $pausedWarned)){
      $pausedWarned = $true
      Write-Host ""
      Write-GHWarning "Scan is Paused on the server (may require intervention). Still waiting until timeout. Details: $scanOverviewPage"
    }

  }
  Write-Host ""

  #Timeout is a failure, not a silent success: without this, the job would
  #proceed to report generation against an unfinished scan
  if($scan_status -ne "Ready"){
    Set-GHOutput 'scan_status' "TimedOut ($scan_status)"
    Set-GHOutput 'gate_result' 'error'
    Write-GHError "Scan did not complete within $env:INPUT_WAIT_FOR_ANALYSIS_TIMEOUT_MINUTES minutes (last status: $scan_status). The scan continues on the server: $scanOverviewPage"
    Add-GHSummary "## :hourglass: AppScan DAST scan timed out in CI`n"
    Add-GHSummary "The job waited **$env:INPUT_WAIT_FOR_ANALYSIS_TIMEOUT_MINUTES minutes** but the scan is still ``$scan_status``. It continues on the AppScan server; results will appear there when done.`n"
    Add-GHSummary "**Scan ID:** ``$global:scanId``  "
    Add-GHSummary "**Scan view:** $scanOverviewPage`n"
    Write-Error "Scan did not reach 'Ready' within the configured timeout. Failing the job."
    Exit 1
  }

  Set-GHOutput 'scan_status' 'Ready'
  Write-GHNotice "DAST scan completed successfully (scan ID: $global:scanId)."
}
function Run-ASoC-GenerateReport ($scanID) {

  $params = @{
    Uri         = "$global:BaseAPIUrl/Reports/Security/Scan/$scanID"
    Method      = 'POST'
    Headers = @{
      'Content-Type' = 'application/json'
      Authorization = "Bearer $global:BearerToken"
    }
  }
  $body = @{
    'Configuration' = @{
      'Summary' = $true
      'Details' = $true
      'Discussion' = $true
      'Overview' = $true
      'TableOfContent' = $true
      'Advisories' = $true
      'FixRecommendation' = $true
      'History' = $true
      'Coverage' = $true
      'MinimizeDetails' = $true
      'Articles' = $true
      'ReportFileType' = "HTML"
      'Title' = "$global:scan_name"
      'Locale' = "en-US"
      'Notes' = "Github SHA: $env:GITHUB_SHA"
      'Comments' = $true
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)
  Write-Debug ($body | Format-Table | Out-String)

  #$output_runreport = Invoke-RestMethod @params -Body ($body|ConvertTo-Json)
  if ($global:SkipCert) {
	$output_runreport = Invoke-RestMethod @params -Body ($body|ConvertTo-Json) -SkipCertificateCheck
  } else {
	$output_runreport = Invoke-RestMethod @params -Body ($body|ConvertTo-Json)
  }
  $report_ID = $output_runreport.Id
  return $report_ID
}

function Run-ASoC-GenerateReportForExecution ($executionId) {

  # Per-EXECUTION report: one report for a specific scan execution.
  # Verified against the AppScan 360 v4 Swagger:
  #   POST /api/v4/Reports/Security/{scope}/{id}  with scope = ScanExecution.
  # Body is identical to the proven per-scan report (Run-ASoC-GenerateReport),
  # so the server treats it the same; only scope/id and Title differ.
  $params = @{
    Uri         = "$global:BaseAPIUrl/Reports/Security/ScanExecution/$executionId"
    Method      = 'POST'
    Headers = @{
      'Content-Type' = 'application/json'
      Authorization = "Bearer $global:BearerToken"
    }
  }
  $body = @{
    'Configuration' = @{
      'Summary' = $true
      'Details' = $true
      'Discussion' = $true
      'Overview' = $true
      'TableOfContent' = $true
      'Advisories' = $true
      'FixRecommendation' = $true
      'History' = $true
      'Coverage' = $true
      'MinimizeDetails' = $true
      'Articles' = $true
      'ReportFileType' = "HTML"
      'Title' = "$global:scan_name (execution $executionId)"
      'Locale' = "en-US"
      'Notes' = "Github SHA: $env:GITHUB_SHA"
      'Comments' = $true
    }
  }
  if ($global:SkipCert) {
    $output_runreport = Invoke-RestMethod @params -Body ($body|ConvertTo-Json) -SkipCertificateCheck
  } else {
    $output_runreport = Invoke-RestMethod @params -Body ($body|ConvertTo-Json)
  }
  return $output_runreport.Id
}

function Run-ASoC-ReportCompletionChecker($reportID){

  #Wait for report
  #/api/v4/Reports $filter= Id eq <ReportId>
  $params = @{
    Uri         = "$global:BaseAPIUrl/Reports" + "?%24filter=Id%20eq%20" + $reportID
    Method      = 'GET'
    Headers = @{
      'Content-Type' = 'application/json'
      Authorization = "Bearer $global:BearerToken"
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  $report_status ="Not Ready"
  while($report_status -ne "Ready"){
    #$json = Invoke-RestMethod @params
    if ($global:SkipCert) {
		$json = Invoke-RestMethod @params -SkipCertificateCheck
    } else {
		$json = Invoke-RestMethod @params
    }
	$output = $json.Items[0]
    $report_status = $output.Status
    Start-Sleep -Seconds 5
    Write-Host "Generating Report... Progress: " $output.Progress "%"
  } 
}

function Run-ASoC-DownloadReport($reportID, $outFileName){

  #Download Report
  #/api/v4/Reports/{ReportId}/Download
  $params = @{
    Uri         = "$global:BaseAPIUrl/Reports/$reportID/Download"
    Method      = 'GET'
    Headers = @{
      'Accept' = 'text/html'
      Authorization = "Bearer $global:BearerToken"
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  #$output_runreport = Invoke-RestMethod @params
  if ($global:SkipCert) {
	$output_runreport = Invoke-RestMethod @params -SkipCertificateCheck
  } else {
	$output_runreport = Invoke-RestMethod @params
  }
  $reportFileName = $outFileName
  if([string]::IsNullOrEmpty($reportFileName)){
    $reportFileName = "AppScan_Security_Report-$env:GITHUB_SHA.html"
  }
  Out-File -InputObject $output_runreport -FilePath ".\$reportFileName"
  Write-Host "Report downloaded to workspace: $reportFileName"
  return $reportFileName
}
#policies options are 'All' or 'None'
function Run-ASoC-GetIssueCount($scanID, $policyScope){

  #/api/v4/Issues/Scan/<scanID>?applyPolicies=all&$filter=status eq 'Open' or Status eq 'InProgress' or Status eq 'Reopened' &$apply=groupby((Status,Severity),aggregate($count as N))
  $params = @{
      Uri         = "$global:BaseAPIUrl/Issues/Scan/$scanID"+"?applyPolicies="+"$policyScope"+"&%24filter=Status%20eq%20%27Open%27%20or%20Status%20eq%20%27InProgress%27%20or%20Status%20eq%20%27Reopened%27&%24apply=groupby%28%28Status%2CSeverity%29%2Caggregate%28%24count%20as%20N%29%29"
      Method      = 'GET'
      Headers = @{
      'Content-Type' = 'application/json'
      Authorization = "Bearer $global:BearerToken"
      }
  }
  
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  #$jsonOutput = Invoke-RestMethod @params
   if ($global:SkipCert) {
	$jsonOutput = Invoke-RestMethod @params -SkipCertificateCheck
  } else {
	$jsonOutput = Invoke-RestMethod @params
  }
  #DEBUG
  #$jsonOutput

  return $jsonOutput.Items

}

function FailBuild-ByNonCompliance($issueCountJson){
  
  $failBuild = $false
  $totalIssues = 0
  foreach($i in $issueCountJson){
    $totalIssues = $totalIssues + $i.Count
  }
  
  #DEBUG
  Write-Host "Total issues: $totalIssues"
  if($totalIssues -gt 0){
    $failBuild = $true
  }
  return $failBuild
}


function FailBuild-BySeverity($issueCountJson, $failureThresholdText){

  #0 = Informational
  #1 = Low
  #2 = Medium
  #3 = High
  #4 = Critical
  $failureThresholdNum = 0
  $failureThresholdNum = Get-SeverityValue($failureThresholdText)
  $totalIssuesCountAboveThreshold = 0
  $failBuild = $false

  foreach($i in $issueCountJson){
    $sevNum = Get-SeverityValue($i.Severity)
    if($sevNum -ge $failureThresholdNum){
      $totalIssuesCountAboveThreshold = $totalIssuesCountAboveThreshold + $i.Count
    }
  }
  
  #DEBUG
  Write-Host "Total count of issues above threshold: $totalIssuesCountAboveThreshold"

  if($totalIssuesCountAboveThreshold -gt 0){
    $failBuild = $true
  }
  return $failBuild
}


function Get-SeverityValue($severityText){

  $severityValue = 1;

  switch($severityText){
    'Informational' {$severityValue = 0;break}
    'Low'           {$severityValue = 1;break}
    'Medium'        {$severityValue = 2;break}
    'High'          {$severityValue = 3;break}
    'Critical'      {$severityValue = 4;break}
  }
  return $severityValue

}

function Run-ASoC-GetAllIssuesFromScan($scanId){

  #Download Report
  $params = @{
    Uri         = "$global:BaseAPIUrl/Issues/Scan/$scanId"+"?applyPolicies=None"
    Method      = 'GET'
    Headers = @{
      'Accept' = 'text/html'
      Authorization = "Bearer $global:BearerToken"
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  #$jsonIssues = Invoke-RestMethod @params
   if ($global:SkipCert) {
	$jsonIssues = Invoke-RestMethod @params -SkipCertificateCheck
  } else {
	$jsonIssues = Invoke-RestMethod @params
  }
  return $jsonIssues
}

function Run-ASoC-SetCommentForIssue($scanId, $issueId, $inputComment){
  #Download Report
  $params = @{
    Uri         = "$global:BaseAPIUrl/Issues/Scan/$scanId"+"?odataFilter=Id%20eq%20"+$issueId
    Method      = 'PUT'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }
  $jsonBody =@{
    Comment = $inputComment
  }
  #DEBUG
  #Write-Debug ($params | Format-Table | Out-String)

  #$jsonOutput = Invoke-RestMethod @params -Body ($jsonBody|ConvertTo-JSON) 
   if ($global:SkipCert) {
	$jsonOutput = Invoke-RestMethod @params -Body ($jsonBody|ConvertTo-JSON) -SkipCertificateCheck
  } else {
	$jsonOutput = Invoke-RestMethod @params -Body ($jsonBody|ConvertTo-JSON) 
  }
  return "Done"
}

#DELETE
function Run-ASoC-SetBatchComments($scanId, $inputComment){


  $params = @{
    Uri         = "$global:BaseAPIUrl/Issues/Scan/$scanId"+"applyPolicies=None"
    Method      = 'PUT'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }
  $jsonBody =@{
    Comment = $inputComment
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  #$jsonOutput = Invoke-RestMethod @params -Body ($jsonBody|ConvertTo-JSON) 
   if ($global:SkipCert) {
	$jsonOutput = Invoke-RestMethod @params -Body ($jsonBody|ConvertTo-JSON) -SkipCertificateCheck
  } else {
	$jsonOutput = Invoke-RestMethod @params -Body ($jsonBody|ConvertTo-JSON)
  }
  return $jsonOutput
}
function Run-ASoC-GetScanDetails($scanId){
  
  #$latestScanExecutionId = ''

  $params = @{
    Uri         = "$global:BaseAPIUrl/Scans/"+"?%24filter=Id%20eq%20"+$scanId
    Method      = 'GET'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  #$response = Invoke-RestMethod @params
   if ($global:SkipCert) {
	$response = Invoke-RestMethod @params -SkipCertificateCheck
  } else {
	$response = Invoke-RestMethod @params
  }
  $array = $response.Items
  $jsonOutput = $array[0]
  #$latestScanExecutionId = $jsonOutput.LatestExecution.Id
  return $jsonOutput

}


function Run-ASoC-CancelScanExecution($executionId){

  $params = @{
    Uri         = "$global:BaseAPIUrl/Scans/Execution/$executionId/"
    Method      = 'DELETE'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  #$jsonOutput = Invoke-WebRequest @params
   if ($global:SkipCert) {
	$jsonOutput = Invoke-WebRequest @params -SkipCertificateCheck
  } else {
	$jsonOutput = Invoke-WebRequest @params
  }
  Write-Debug $jsonOutput
  return $jsonOutput
}

function Delete-LatestRunningScanExecution($scanId){

  $ExecutionId = ''
  $ExecutionProgress = ''

  $scanDetailJson = Run-ASoC-GetScanDetails($scanId)

  $ExecutionId = $scanDetailJson.LatestExecution.Id
  $ExecutionProgress = $scanDetailJson.LatestExecution.ExecutionProgress

  if($ExecutionProgress -ne 'Completed'){

    $cancelStatus = Run-ASoC-CancelScanExecution($ExecutionId)
    Write-Debug $cancelStatus
    
    if($cancelStatus.StatusCode -In 200..299){
      Write-Host "Latest Scan Execution with Execution ID: $ExecutionId is successfully cancelled."
    }else{
      Write-Host "Cancellation of Scan with Execution ID: $executionId unsuccessful. See debug output:"
      Write-Host $cancelStatus
    }

  }else{
    Write-Host "Latest scan execution ID: $ExecutionId is already completed and not occupying a scan queue."
  }
}

#Epheremal presence related functions
function Run-ASoC-CreatePresence($presenceName){
  
  #CREATE PRESENCE
  $params = @{
    Uri         = "$global:BaseAPIUrl/Presences"
    Method      = 'POST'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }
  $jsonBody =@{
    PresenceName = $presenceName
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  #$jsonOutput = Invoke-RestMethod @params -Body ($jsonBody|ConvertTo-JSON)
   if ($global:SkipCert) {
	$jsonOutput = Invoke-RestMethod @params -Body ($jsonBody|ConvertTo-JSON) -SkipCertificateCheck
  } else {
	$jsonOutput = Invoke-RestMethod @params -Body ($jsonBody|ConvertTo-JSON)
  }
  
  $presenceId = $jsonOutput.Id
  return $presenceId


}

function Run-ASoC-DownloadPresence($presenceId, $OutputFileName, $platform){

  #DOWNLOAD PRESENCE ZIP FILE
  $params = @{
    Uri         = "$global:BaseAPIUrl/Presences/"+$presenceId+"/Download/"+$platform
    Method      = 'GET'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  $ProgressPreference = 'SilentlyContinue'
  #$jsonOutput = Invoke-WebRequest @params -OutFile $OutputFileName
  if ($global:SkipCert) {
		$jsonOutput = Invoke-WebRequest @params -OutFile $OutputFileName -SkipCertificateCheck
  } else {
		$jsonOutput = Invoke-WebRequest @params -OutFile $OutputFileName
  }
  $ProgressPreference = 'Continue'
  
  return $jsonOutput
}


function Run-ASoC-DeletePresence($presenceId){

  $params = @{
    Uri         = "$global:BaseAPIUrl/Presences/"+$presenceId
    Method      = 'DELETE'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  $response = ""
  try {
    #$response = Invoke-WebRequest @params
	 if ($global:SkipCert) {
		$response = Invoke-WebRequest @params -SkipCertificateCheck
    } else {
		$response = Invoke-WebRequest @params
    }
    Write-Host "Successfully deleted presence with ID: $presenceId"

    
  }
  catch {
      Write-Host "Failed to delete presence with ID: $presenceId"
      Write-Host "The request failed with error: $($_.Exception.Message)"
      Write-Host "The request failed with HTTP status code $($response.StatusCode)"
      Write-Host "The failure message is: $($response.StatusDescription)"
    }
  
}


function Run-ASoC-GetPresenceIdGivenPresenceName($presenceName){

  $params = @{
    Uri         = "$global:BaseAPIUrl/Presences"
    Method      = 'GET'
    Headers = @{
      Authorization = "Bearer $global:BearerToken"
      'Content-Type' = 'application/json'
    }
  }
  #DEBUG
  Write-Debug ($params | Format-Table | Out-String)

  #$response = Invoke-RestMethod @params
   if ($global:SkipCert) {
	$response = Invoke-RestMethod @params -SkipCertificateCheck
  } else {
	$response = Invoke-RestMethod @params
  }
  $array = $response.Items

  foreach($i in $array){
    if($i.PresenceName -eq $presenceName){
      return $i.Id
    }
  }
}

function Run-ASoC-CheckPresenceStatus($presenceId){

    #CREATE PRESENCE
    $params = @{
      Uri         = "$global:BaseAPIUrl/Presences?%24filter=Id%20eq%20"+$presenceId
      Method      = 'GET'
      Headers = @{
        Authorization = "Bearer $global:BearerToken"
        'Content-Type' = 'application/json'
      }
    }
    #DEBUG
    Write-Debug ($params | Format-Table | Out-String)
  
    #$response = Invoke-RestMethod @params
	 if ($global:SkipCert) {
		$response = Invoke-RestMethod @params -SkipCertificateCheck
    } else {
		$response = Invoke-RestMethod @params
    }
    $array = $response.Items
    $jsonOutput = $array[0]
    
    if($jsonOutput.Status -eq 'Active'){
      Write-Host "AppScan Presence with ID: $presenceId is in active state. "
      return $true
    }else{
      Write-Host "AppScan Presence with ID:" $presenceId "is NOT yet in active state. State =" $array.Status
      return $false
    }
}

#Creates a ephemeral presence. Returns the presenceId if successful.
function Create-EphemeralPresenceWithDocker{

  #$global:ephemeralPresenceName = "Github $env:GITHUB_SHA"
  $presenceName = $global:ephemeralPresenceName
  $presenceFileName = 'presence.zip'
  $presenceFolder = 'presence'
  $platform = 'linux_x64'

  #DELETE PRESENCE IF PRESENT
  $presenceId = Run-ASoC-GetPresenceIdGivenPresenceName($presenceName)
  if($presenceId){
    Run-ASoC-DeletePresence($presenceId)
  }
  

  #CREATE A NEW PRESENCE
  $presenceId = Run-ASoC-CreatePresence($presenceName)
  $output = Run-ASoC-DownloadPresence $presenceId $presenceFileName $platform

  $dockerContainerName = 'appscanpresence_container'
  $dockerImageName = 'appscanpresence_image'
  $dockerfileName = 'dockerfile'

  #Start presence in a container
  if ((docker ps -a --format '{{.Names}}') -contains $dockerContainerName) {
    docker stop $dockerContainerName
    docker rm $dockerContainerName
  }

  Write-Host "Creating docker image..."
  (docker build -f $env:GITHUB_ACTION_PATH/$dockerfileName -t $dockerImageName .) 2>&1
  
  Write-Host "Starting container..."
  docker run --name $dockerContainerName -d $dockerImageName

  #Pause for 5 seconds for the commands to complete
  Start-Sleep -Seconds 5

  #Get latest docker log
  Write-Host "Getting Latest Appscan Presence Log from the container:"
  docker logs $dockerContainerName

  #Check if presence is up and running

  $i = 1
  $checkPresenceMaxCount = 5 #Number of times to check if Presence is up and running
  $pauseDuration = 5 #pause duration in seconds
  $presenceStatus = $false
  while(($i -le $checkPresenceMaxCount) -and ($presenceStatus -eq $false)){

    Write-Host "Checking for Presence Status from ASoC..."
    $presenceStatus = Run-ASoC-CheckPresenceStatus($presenceId)
    Start-Sleep -Seconds $pauseDuration
    $i = $i + 1

  }

  if($presenceStatus){
      Write-Host "Ephemeral Presence is deployed and running"
      $global:ephemeralPresenceId = $presenceId
  }else{
    Write-Error "Ephemeral Presence creation failed. Presence status = $presenceStatus"
    exit 1
  }
}
