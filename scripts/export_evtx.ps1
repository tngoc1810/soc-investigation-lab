<#
.SYNOPSIS
Export existing EVTX evidence to the soclab JSONL interchange format.
.DESCRIPTION
Reads an EVTX file, does not run commands contained in events, enable auditing,
install Sysmon or change the computer's security settings. Stores original XML
and the EVTX SHA-256. The JSONL export is sensitive evidence; keep it local.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InputPath,
    [Parameter(Mandatory = $true)][string]$OutputPath
)
$ErrorActionPreference = 'Stop'
$taskInput = (Resolve-Path -LiteralPath $InputPath).Path
$taskOutput = [System.IO.Path]::GetFullPath($OutputPath)
if ([System.IO.Path]::GetExtension($taskInput) -ne '.evtx') { throw 'Input must be an .evtx file' }
if (Test-Path -LiteralPath $taskOutput) { throw 'Output already exists; use a new path' }
$taskParent = [System.IO.Path]::GetDirectoryName($taskOutput)
[System.IO.Directory]::CreateDirectory($taskParent) | Out-Null
$taskHash = (Get-FileHash -LiteralPath $taskInput -Algorithm SHA256).Hash.ToLowerInvariant()
$taskTemporary = $taskOutput + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
$taskWriter = [System.IO.StreamWriter]::new($taskTemporary, $false, [System.Text.UTF8Encoding]::new($false))
$taskCount = 0
try {
    # EventLogReader accepts a literal file path, avoiding wildcard expansion.
    $taskQuery = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new($taskInput, [System.Diagnostics.Eventing.Reader.PathType]::FilePath)
    $taskReader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($taskQuery)
    try {
        while ($null -ne ($taskEvent = $taskReader.ReadEvent())) {
            try {
                $taskXmlText = $taskEvent.ToXml()
                [xml]$taskXml = $taskXmlText
                $taskNs = [System.Xml.XmlNamespaceManager]::new($taskXml.NameTable)
                $taskNs.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
                $taskData = [ordered]@{}
                $taskIndex = 0
                foreach ($taskNode in $taskXml.SelectNodes('/e:Event/e:EventData/e:Data', $taskNs)) {
                    $taskName = $taskNode.GetAttribute('Name')
                    if ([string]::IsNullOrWhiteSpace($taskName)) { $taskName = "Data_$taskIndex" }
                    if ($taskData.Contains($taskName)) { throw "Duplicate EventData field: $taskName" }
                    $taskData[$taskName] = [string]$taskNode.InnerText
                    $taskIndex++
                }
                # Some events, including 1102, use nested UserData with another namespace.
                foreach ($taskNode in $taskXml.SelectNodes('/e:Event/e:UserData//*[not(*)]', $taskNs)) {
                    $taskName = $taskNode.LocalName
                    if ($taskData.Contains($taskName)) { throw "Duplicate UserData field: $taskName" }
                    $taskData[$taskName] = [string]$taskNode.InnerText
                }
                $taskSystem = $taskXml.SelectSingleNode('/e:Event/e:System', $taskNs)
                $taskTimestamp = $taskSystem.SelectSingleNode('e:TimeCreated', $taskNs).GetAttribute('SystemTime')
                $taskObject = [ordered]@{
                    timestamp = $taskTimestamp
                    host = [string]$taskSystem.SelectSingleNode('e:Computer', $taskNs).InnerText
                    channel = [string]$taskSystem.SelectSingleNode('e:Channel', $taskNs).InnerText
                    provider = $taskSystem.SelectSingleNode('e:Provider', $taskNs).GetAttribute('Name')
                    event_id = [int]$taskSystem.SelectSingleNode('e:EventID', $taskNs).InnerText
                    record_id = [long]$taskSystem.SelectSingleNode('e:EventRecordID', $taskNs).InnerText
                    event_data = $taskData
                    original_xml = $taskXmlText
                    provenance = [ordered]@{ evtx_filename = [System.IO.Path]::GetFileName($taskInput); evtx_sha256 = $taskHash }
                }
                $taskWriter.WriteLine(($taskObject | ConvertTo-Json -Depth 20 -Compress))
                $taskCount++
            } finally { $taskEvent.Dispose() }
        }
    } finally { $taskReader.Dispose() }
    if ($taskCount -eq 0) { throw 'EVTX contains no readable events' }
    $taskWriter.Dispose()
    [System.IO.File]::Move($taskTemporary, $taskOutput)
    Write-Output "Exported $taskCount events. EVTX SHA-256: $taskHash"
} catch {
    $taskWriter.Dispose()
    if (Test-Path -LiteralPath $taskTemporary) { Remove-Item -LiteralPath $taskTemporary }
    throw
}
