<# Pinned native Windows lab backend; no services, firewall changes or administrator install. #>
[CmdletBinding()]
param([ValidateSet('Install','Start','Stop','Status')][string]$Action = 'Status', [ValidateSet('All','Loki','Grafana')][string]$Component = 'All')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskRuntime = Join-Path $env:LOCALAPPDATA 'SOCInvestigationLab/runtime'
[System.IO.Directory]::CreateDirectory($taskRuntime) | Out-Null
$taskLock = Get-Content (Join-Path $taskRoot 'deployment/runtime-lock.json') -Raw | ConvertFrom-Json
$taskState = Join-Path $taskRuntime 'processes.json'
$taskSecrets = Join-Path $taskRuntime 'local-credentials.json'
$taskNames = if ($Component -eq 'All') { @('loki','grafana') } else { @($Component.ToLowerInvariant()) }
function Get-TaskProcesses($taskRecords) {
    $taskOwned = @()
    foreach ($taskRecord in $taskRecords) {
        $taskMain = Get-Process -Id $taskRecord.id -ErrorAction SilentlyContinue
        if ($taskMain -and $taskMain.Path -eq $taskRecord.path) { $taskOwned += [pscustomobject]@{process=$taskMain;path=$taskRecord.path;role='main'} }
        if ([System.IO.Path]::GetFileName($taskRecord.path) -eq 'grafana.exe') {
            $taskPluginRoot = [System.IO.Path]::GetFullPath((Join-Path $taskRuntime 'grafana'))+[System.IO.Path]::DirectorySeparatorChar
            foreach ($taskChild in (Get-CimInstance Win32_Process -Filter "ParentProcessId = $($taskRecord.id)")) {
                if ($taskChild.ExecutablePath -and $taskChild.ExecutablePath.StartsWith($taskPluginRoot,[System.StringComparison]::OrdinalIgnoreCase)) {
                    $taskPlugin = Get-Process -Id $taskChild.ProcessId -ErrorAction SilentlyContinue
                    if ($taskPlugin -and $taskPlugin.Path -eq $taskChild.ExecutablePath) { $taskOwned += [pscustomobject]@{process=$taskPlugin;path=$taskChild.ExecutablePath;role='grafana-plugin'} }
                }
            }
        }
    }
    return $taskOwned
}
if ($Action -eq 'Install') {
    foreach ($taskName in $taskNames) {
        $taskSpec = $taskLock.$taskName
        $taskArchive = Join-Path $taskRuntime ($taskName + '-' + $taskSpec.version + '.' + $taskSpec.format)
        if (-not (Test-Path -LiteralPath $taskArchive)) {
            if ($taskName -eq 'grafana' -and (Get-Command python -ErrorAction SilentlyContinue)) {
                python (Join-Path $PSScriptRoot 'fetch_runtime.py') grafana
                if ($LASTEXITCODE -ne 0) { throw 'Resumable Grafana download failed' }
            } else {
            $taskPartial = $taskArchive + '.partial'
            if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
                curl.exe --fail --location --silent --show-error --continue-at - --max-time 1800 --output $taskPartial $taskSpec.url
                if ($LASTEXITCODE -ne 0) { throw 'Runtime download failed; partial file retained for resume' }
            } else { Invoke-WebRequest -Uri $taskSpec.url -OutFile $taskPartial }
            if ((Get-FileHash -LiteralPath $taskPartial -Algorithm SHA256).Hash.ToLowerInvariant() -ne $taskSpec.sha256) { throw "Runtime hash mismatch: $taskName" }
            Move-Item -LiteralPath $taskPartial -Destination $taskArchive
            }
        }
        if ((Get-FileHash -LiteralPath $taskArchive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $taskSpec.sha256) { throw "Runtime hash mismatch: $taskName" }
        $taskTarget = Join-Path $taskRuntime $taskName
        if (-not (Test-Path -LiteralPath $taskTarget)) {
            [System.IO.Directory]::CreateDirectory($taskTarget) | Out-Null
            if ($taskSpec.format -eq 'zip') { Expand-Archive -LiteralPath $taskArchive -DestinationPath $taskTarget }
            else { tar -xzf $taskArchive -C $taskTarget; if ($LASTEXITCODE -ne 0) { throw 'Runtime archive extraction failed' } }
        }
        Write-Output "Verified and extracted $taskName $($taskSpec.version)"
    }
    exit
}
if ($Action -eq 'Start') {
    if (Test-Path -LiteralPath $taskState) {
        $taskOld = Get-Content -LiteralPath $taskState -Raw | ConvertFrom-Json
        foreach ($taskEntry in $taskOld) {
            $taskProcess = Get-Process -Id $taskEntry.id -ErrorAction SilentlyContinue
            if ($taskProcess -and $taskProcess.Path -eq $taskEntry.path) { throw 'Lab backend already running; use Status or Stop first' }
        }
    }
    $taskPorts = @()
    if ('loki' -in $taskNames) { $taskPorts += @(3100,9096) }
    if ('grafana' -in $taskNames) { $taskPorts += 3000 }
    foreach ($taskPort in $taskPorts) {
        if (Get-NetTCPConnection -State Listen -LocalPort $taskPort -ErrorAction SilentlyContinue) { throw "Port $taskPort is already in use" }
    }
    $taskLoki = if ('loki' -in $taskNames) { Get-ChildItem -LiteralPath (Join-Path $taskRuntime 'loki') -Filter 'loki-windows-amd64.exe' -Recurse | Select-Object -First 1 } else { $null }
    $taskGrafana = if ('grafana' -in $taskNames) { Get-ChildItem -LiteralPath (Join-Path $taskRuntime 'grafana') -Filter 'grafana.exe' -Recurse | Select-Object -First 1 } else { $null }
    if (('loki' -in $taskNames -and -not $taskLoki) -or ('grafana' -in $taskNames -and -not $taskGrafana)) { throw 'Run runtime.ps1 -Action Install first' }
    if ('grafana' -in $taskNames) {
    if (-not (Test-Path -LiteralPath $taskSecrets)) {
        $taskRandom = New-Object byte[] 32
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($taskRandom)
        $taskPassword = [Convert]::ToBase64String($taskRandom)
        [System.IO.File]::WriteAllText($taskSecrets, (@{user='labadmin';password=$taskPassword} | ConvertTo-Json), [System.Text.UTF8Encoding]::new($false))
    }
    $taskCredentials = Get-Content -LiteralPath $taskSecrets -Raw | ConvertFrom-Json
    $taskProvision = Join-Path $taskRuntime 'provisioning'
    [System.IO.Directory]::CreateDirectory($taskProvision) | Out-Null
    foreach ($taskFolder in @('plugins','alerting')) { [System.IO.Directory]::CreateDirectory((Join-Path $taskProvision $taskFolder)) | Out-Null }
    Copy-Item -LiteralPath (Join-Path $taskRoot 'deployment/provisioning/datasources') -Destination $taskProvision -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $taskRoot 'deployment/provisioning/dashboards') -Destination $taskProvision -Recurse -Force
    $taskProvider = Join-Path $taskProvision 'dashboards/providers.yaml'
    $taskProviderText = (Get-Content -LiteralPath $taskProvider -Raw).Replace('__DASHBOARD_PATH__',(Join-Path $taskRoot 'deployment/dashboards').Replace('\','/'))
    [System.IO.File]::WriteAllText($taskProvider,$taskProviderText,[System.Text.UTF8Encoding]::new($false))
    foreach ($taskFolder in @('grafana-data','grafana-logs','grafana-plugins')) { [System.IO.Directory]::CreateDirectory((Join-Path $taskRuntime $taskFolder)) | Out-Null }
    $taskIni = (Get-Content (Join-Path $taskRoot 'deployment/grafana.ini') -Raw).Replace('__PROVISIONING_PATH__',$taskProvision.Replace('\','/')).Replace('__RUNTIME_PATH__',$taskRuntime.Replace('\','/')).Replace('__RUNTIME_ADMIN_PASSWORD__',$taskCredentials.password)
    [System.IO.File]::WriteAllText((Join-Path $taskRuntime 'grafana.ini'),$taskIni,[System.Text.UTF8Encoding]::new($false))
    }
    Copy-Item -LiteralPath (Join-Path $taskRoot 'deployment/loki.yaml') -Destination (Join-Path $taskRuntime 'loki.yaml') -Force
    $taskPreviousMemoryLimit = $env:GOMEMLIMIT
    $env:GOMEMLIMIT = '128MiB'
    $taskEntries = @()
    try {
        if ('loki' -in $taskNames) {
        $taskLokiProcess = Start-Process -FilePath $taskLoki.FullName -ArgumentList '-config.file=loki.yaml' -WorkingDirectory $taskRuntime -WindowStyle Hidden -RedirectStandardOutput (Join-Path $taskRuntime 'loki.stdout.log') -RedirectStandardError (Join-Path $taskRuntime 'loki.stderr.log') -PassThru
        $taskEntries += @{id=$taskLokiProcess.Id;path=$taskLoki.FullName}
        }
        if ('grafana' -in $taskNames) {
        $taskGrafanaHome = Split-Path -Parent (Split-Path -Parent $taskGrafana.FullName)
        $taskArgs = @('server','--homepath',('"'+$taskGrafanaHome+'"'),'--config',('"'+(Join-Path $taskRuntime 'grafana.ini')+'"'))
        $taskGrafanaProcess = Start-Process -FilePath $taskGrafana.FullName -ArgumentList $taskArgs -WorkingDirectory $taskRuntime -WindowStyle Hidden -RedirectStandardOutput (Join-Path $taskRuntime 'grafana.stdout.log') -RedirectStandardError (Join-Path $taskRuntime 'grafana.stderr.log') -PassThru
        $taskEntries += @{id=$taskGrafanaProcess.Id;path=$taskGrafana.FullName}
        }
        [System.IO.File]::WriteAllText($taskState,($taskEntries | ConvertTo-Json),[System.Text.UTF8Encoding]::new($false))
    } catch {
        # A failure launching the second component must not orphan the first.
        foreach ($taskOwned in (Get-TaskProcesses $taskEntries)) {
            $taskProcess = Get-Process -Id $taskOwned.process.Id -ErrorAction SilentlyContinue
            if ($taskProcess -and $taskProcess.Path -eq $taskOwned.path) { Stop-Process -Id $taskProcess.Id }
        }
        [System.IO.File]::WriteAllText($taskState,'[]',[System.Text.UTF8Encoding]::new($false))
        throw
    } finally { $env:GOMEMLIMIT = $taskPreviousMemoryLimit }
    $taskHealth = @()
    if ('loki' -in $taskNames) { $taskHealth += 'http://127.0.0.1:3100/ready' }
    if ('grafana' -in $taskNames) { $taskHealth += 'http://127.0.0.1:3000/api/health' }
    $taskDeadline = [DateTime]::UtcNow.AddSeconds(120)
    do {
        $taskReady = $true
        $taskFailed = $false
        foreach ($taskEntry in $taskEntries) {
            $taskProcess = Get-Process -Id $taskEntry.id -ErrorAction SilentlyContinue
            if (-not $taskProcess) { $taskFailed = $true }
        }
        if ($taskFailed) { $taskReady = $false; break }
        foreach ($taskUrl in $taskHealth) {
            try { $null = Invoke-WebRequest -Uri $taskUrl -TimeoutSec 2 -UseBasicParsing }
            catch { $taskReady = $false }
        }
        if ($taskReady) { break }
        Start-Sleep -Seconds 1
    } while ([DateTime]::UtcNow -lt $taskDeadline)
    if (-not $taskReady) {
        foreach ($taskOwned in (Get-TaskProcesses $taskEntries)) {
            $taskProcess = Get-Process -Id $taskOwned.process.Id -ErrorAction SilentlyContinue
            if ($taskProcess -and $taskProcess.Path -eq $taskOwned.path) { Stop-Process -Id $taskProcess.Id }
        }
        throw 'Backend readiness failed; newly started lab processes stopped. Inspect %LOCALAPPDATA%/SOCInvestigationLab/runtime/*.log.'
    }
    Write-Output "Ready: $($taskNames -join ', '). Loki 127.0.0.1:3100; Grafana 127.0.0.1:3000. Credentials stay in the local runtime cache outside the repository."
    exit
}
if (Test-Path -LiteralPath $taskState) {
    foreach ($taskOwned in (Get-TaskProcesses (Get-Content -LiteralPath $taskState -Raw | ConvertFrom-Json))) {
        $taskProcess = Get-Process -Id $taskOwned.process.Id -ErrorAction SilentlyContinue
        if ($taskProcess -and $taskProcess.Path -eq $taskOwned.path) {
            if ($Action -eq 'Stop') { Stop-Process -Id $taskProcess.Id; Write-Output "Stopped lab process $($taskProcess.Id)" }
            else { [pscustomobject]@{ Name=$taskProcess.ProcessName; Role=$taskOwned.role; PID=$taskProcess.Id; WorkingSetMiB=[math]::Round($taskProcess.WorkingSet64/1MB,2); PeakWorkingSetMiB=[math]::Round($taskProcess.PeakWorkingSet64/1MB,2) } }
        }
    }
} else { Write-Output 'No lab backend process state.' }
