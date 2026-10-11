param([Parameter(Mandatory=$true)][string]$InputPath)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$taskBlocks = Get-Content -LiteralPath $InputPath -Raw -Encoding UTF8 | ConvertFrom-Json
$taskResults = @()
foreach ($taskBlock in $taskBlocks) {
    $taskTokens = $null
    $taskErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseInput($taskBlock.text, [ref]$taskTokens, [ref]$taskErrors)
    if ($taskErrors.Count -gt 0) {
        throw "PowerShell syntax failed in $($taskBlock.document): $($taskErrors[0].Message)"
    }
    $taskResults += @{document=$taskBlock.document; syntax_valid=$true}
}
ConvertTo-Json -InputObject @($taskResults) -Depth 4 -Compress
