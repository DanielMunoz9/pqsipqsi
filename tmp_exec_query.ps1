$ErrorActionPreference = 'Stop'
$proc = $null
try {
  if (Test-Path .\backend_stdout.log) { Remove-Item .\backend_stdout.log -Force }
  if (Test-Path .\backend_stderr.log) { Remove-Item .\backend_stderr.log -Force }

  Get-Content .\.env | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith('#')) {
      $parts = $line -split '=',2
      if ($parts.Count -eq 2) {
        [System.Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim())
      }
    }
  }
  [System.Environment]::SetEnvironmentVariable('PORT','8080')

  $proc = Start-Process -FilePath .\valhala.exe -RedirectStandardOutput .\backend_stdout.log -RedirectStandardError .\backend_stderr.log -PassThru

  $ready = $false
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  while ($sw.Elapsed.TotalSeconds -lt 60) {
    try {
      $resp = Invoke-WebRequest -Uri http://127.0.0.1:8080/ -UseBasicParsing -Method Get -TimeoutSec 2
      if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 500) { $ready = $true; break }
    } catch {
      try {
        $tcp = Test-NetConnection -ComputerName 127.0.0.1 -Port 8080 -WarningAction SilentlyContinue
        if ($tcp.TcpTestSucceeded) { $ready = $true; break }
      } catch {}
    }
  }
  Write-Output ('READINESS=' + $ready)

  $ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $pseud = 'debug_profilefix_' + $ts
  $payload = @{
    pseudonimo = $pseud
    exam_passed = $true
    exam_score = 10
    is_upgrade = $false
    division = 'Ciudad'
  } | ConvertTo-Json -Depth 4

  $postStatus = $null
  $postBodyText = $null
  try {
    $postResp = Invoke-WebRequest -Uri http://127.0.0.1:8080/api/inscribir -Method Post -ContentType application/json -Body $payload -TimeoutSec 20
    $postStatus = [int]$postResp.StatusCode
    $postBodyText = $postResp.Content
  } catch {
    $ex = $_.Exception
    if ($ex.Response) {
      $postStatus = [int]$ex.Response.StatusCode
      $reader = New-Object System.IO.StreamReader($ex.Response.GetResponseStream())
      $postBodyText = $reader.ReadToEnd()
      $reader.Close()
    } else {
      $postStatus = -1
      $postBodyText = $ex.Message
    }
  }

  Write-Output ('PSEUDONYM=' + $pseud)
  Write-Output ('HTTP_STATUS=' + $postStatus)
  Write-Output ('HTTP_BODY=' + $postBodyText)

  $supabaseUrl = [System.Environment]::GetEnvironmentVariable('SUPABASE_URL')
  $supabaseKey = [System.Environment]::GetEnvironmentVariable('SUPABASE_KEY')
  if (-not $supabaseKey) { $supabaseKey = [System.Environment]::GetEnvironmentVariable('SUPABASE_ANON_KEY') }

  $headers = @{ apikey = $supabaseKey; Authorization = ('Bearer ' + $supabaseKey) }

  $auditRow = $null
  $auditColumns = @('pseudonimo')
  foreach ($col in $auditColumns) {
    try {
      $u = $supabaseUrl + '/rest/v1/audit_logs?select=*&' + $col + '=eq.' + [uri]::EscapeDataString($pseud) + '&order=id.desc&limit=1'
      $rows = Invoke-RestMethod -Uri $u -Headers $headers -Method Get
      if ($rows -and $rows.Count -gt 0) { $auditRow = $rows[0]; break }
    } catch {}
  }

  $profileFound = $false
  $profileStatus = $null
  if ($auditRow) {
    $aid = $auditRow.id
    Write-Output ('AUDIT_LOG_ID=' + $aid)
    $pu = $supabaseUrl + '/rest/v1/player_competitive_profiles?select=*&source_audit_log_id=eq.' + $aid + '&order=id.desc&limit=1'
    try {
      $prows = Invoke-RestMethod -Uri $pu -Headers $headers -Method Get
      if ($prows -and $prows.Count -gt 0) {
        $profileFound = $true
        $prow = $prows[0]
        foreach ($k in @('status','profile_status','competitive_status','exam_status')) {
          if ($prow.PSObject.Properties.Name -contains $k) { $profileStatus = $prow.$k; break }
        }
      }
    } catch {}
  }

  Write-Output ('PROFILE_FOUND=' + $profileFound)
  Write-Output ('PROFILE_STATUS=' + $profileStatus)

  Write-Output '--- backend_stderr.log (last 40) ---'
  if (Test-Path .\backend_stderr.log) {
    Get-Content .\backend_stderr.log -Tail 40
  } else {
    Write-Output 'backend_stderr.log no existe'
  }
}
finally {
  if ($proc -and -not $proc.HasExited) {
    Stop-Process -Id $proc.Id -Force
    Write-Output ('BACKEND_STOPPED_PID=' + $proc.Id)
  }
}
