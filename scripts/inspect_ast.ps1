<# Parse saved script TEXT. No dot-source, Invoke-Expression, or command execution. #>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$InputPath,[Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference='Stop'
if (Test-Path -LiteralPath $OutputPath) { throw 'AST output already exists' }
$taskScript=[System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $InputPath).Path)
if ($taskScript.Length -gt 262144) { throw 'Script text exceeds inspection limit' }
$taskTokens=$null
$taskErrors=$null
$taskAst=[System.Management.Automation.Language.Parser]::ParseInput($taskScript,[ref]$taskTokens,[ref]$taskErrors)
$taskCommands=@($taskAst.FindAll({param($taskNode) $taskNode -is [System.Management.Automation.Language.CommandAst]},$true) | ForEach-Object {
    @{name=$_.GetCommandName();text=$_.Extent.Text;line=$_.Extent.StartLineNumber}
})
$taskMethods=@($taskAst.FindAll({param($taskNode) $taskNode -is [System.Management.Automation.Language.InvokeMemberExpressionAst]},$true) | ForEach-Object {$_.Extent.Text})
$taskLiterals=@($taskAst.FindAll({param($taskNode) $taskNode -is [System.Management.Automation.Language.StringConstantExpressionAst]},$true) | ForEach-Object {$_.Value})
$taskResult=@{powershell_version=$PSVersionTable.PSVersion.ToString();parsed_only=$true;commands=$taskCommands;member_invocations=$taskMethods;string_literals=$taskLiterals;parse_errors=@($taskErrors | ForEach-Object {$_.Message});limitation='AST presence does not prove execution: unreachable code, functions and conditions need context.'}
[System.IO.File]::WriteAllText($OutputPath,($taskResult | ConvertTo-Json -Depth 8),[System.Text.UTF8Encoding]::new($false))
Write-Output "Parsed static text with PowerShell $($PSVersionTable.PSVersion); commands=$($taskCommands.Count); methods=$($taskMethods.Count); errors=$($taskErrors.Count)"
