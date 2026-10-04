<# Download only the pinned evidence sample; verify SHA-256 before use. #>
[CmdletBinding()]
param(
    [ValidateSet('public-mshta-task')][string]$Sample = 'public-mshta-task',
    [string]$OutputDirectory = 'data/raw/public'
)
$ErrorActionPreference = 'Stop'
$taskCatalogPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'data/catalog.json'
$taskCatalog = Get-Content -LiteralPath $taskCatalogPath -Raw | ConvertFrom-Json
$taskSample = $taskCatalog.$Sample
$taskDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
[System.IO.Directory]::CreateDirectory($taskDirectory) | Out-Null
$taskTarget = Join-Path $taskDirectory $taskSample.filename
if (Test-Path -LiteralPath $taskTarget) {
    $taskExistingHash = (Get-FileHash -LiteralPath $taskTarget -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($taskExistingHash -ne $taskSample.sha256) { throw 'Existing sample hash differs; evidence was not overwritten' }
    Write-Output 'Verified existing pinned sample.'
    return
}
$taskEncodedPath = ($taskSample.path.Split('/') | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/'
$taskUrl = 'https://raw.githubusercontent.com/Yamato-Security/hayabusa-sample-evtx/' + $taskSample.commit + '/' + $taskEncodedPath
$taskTemporary = $taskTarget + '.' + [guid]::NewGuid().ToString('N') + '.download'
try {
    Invoke-WebRequest -Uri $taskUrl -OutFile $taskTemporary
    $taskActualHash = (Get-FileHash -LiteralPath $taskTemporary -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($taskActualHash -ne $taskSample.sha256) { throw 'Downloaded EVTX failed SHA-256 verification' }
    if ((Get-Item -LiteralPath $taskTemporary).Length -ne $taskSample.size_bytes) { throw 'Unexpected EVTX size' }
    [System.IO.File]::Move($taskTemporary, $taskTarget)
    Write-Output "Downloaded and verified sample: $Sample"
} finally {
    if (Test-Path -LiteralPath $taskTemporary) { Remove-Item -LiteralPath $taskTemporary }
}
