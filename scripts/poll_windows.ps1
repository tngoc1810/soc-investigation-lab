<# One bounded read. Python commits the cursor with evidence; no endpoint settings changed. #>
[CmdletBinding()]
param(
 [ValidateSet('System','Security','Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-PowerShell/Operational')][string]$Channel='System',
 [long]$After=0,
 [string]$AfterHash='',
 [ValidateRange(1,200)][int]$MaxEvents=20,
 [Parameter(Mandatory=$true)][string]$OutputPath
)
$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskPrivate=[IO.Path]::GetFullPath((Join-Path $taskRoot 'data/local'))+[IO.Path]::DirectorySeparatorChar
$taskOutput=[IO.Path]::GetFullPath($OutputPath)
$taskLiveCache=[IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'SOCInvestigationLab/live'))+[IO.Path]::DirectorySeparatorChar
# Packaged desktop hosts can resolve LOCALAPPDATA to their physical MSIX cache.
# Accept only the project-named live subtree inside that private package cache.
$taskPackagePattern='^'+[regex]::Escape([IO.Path]::GetFullPath($env:LOCALAPPDATA))+'\\Packages\\[^\\]+\\LocalCache\\Local\\SOCInvestigationLab\\live\\'
$taskPackaged=[regex]::IsMatch($taskOutput,$taskPackagePattern,[Text.RegularExpressions.RegexOptions]::IgnoreCase)
if (-not ($taskOutput.StartsWith($taskPrivate,[StringComparison]::OrdinalIgnoreCase) -or $taskOutput.StartsWith($taskLiveCache,[StringComparison]::OrdinalIgnoreCase) -or $taskPackaged)) { throw 'Raw evidence must remain under data/local or the private live cache' }
if (Test-Path -LiteralPath $taskOutput) { throw 'Poll output already exists' }
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($taskOutput)) | Out-Null
$taskLatest=Get-WinEvent -LogName $Channel -MaxEvents 1
$taskOldest=Get-WinEvent -LogName $Channel -Oldest -MaxEvents 1
$taskLatestId=[long]$taskLatest.RecordId
$taskOldestId=[long]$taskOldest.RecordId
$taskLatest.Dispose();$taskOldest.Dispose()
$taskReset=($After -gt $taskLatestId)
$taskGap=($After -gt 0 -and ($taskReset -or $After -lt ($taskOldestId-1)))
if ($AfterHash -and $After -ge $taskOldestId -and $After -le $taskLatestId) {
    $taskAnchorErrors=@()
    $taskAnchor=@(Get-WinEvent -LogName $Channel -FilterXPath "*[System[EventRecordID = $After]]" -MaxEvents 1 -ErrorAction SilentlyContinue -ErrorVariable taskAnchorErrors)
    foreach ($taskError in $taskAnchorErrors) { if ($taskError.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw $taskError } }
    if ($taskAnchor.Count) {
        try {
            $taskHasher=[Security.Cryptography.SHA256]::Create()
            try { $taskActualHash=([BitConverter]::ToString($taskHasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($taskAnchor[0].ToXml())))).Replace('-','').ToLowerInvariant() } finally { $taskHasher.Dispose() }
            if ($taskActualHash -ne $AfterHash) { $taskReset=$true;$taskGap=$true }
        } finally { $taskAnchor[0].Dispose() }
    } else { $taskReset=$true;$taskGap=$true }
}
if ($taskReset) { $After=0 }
if ($After -eq 0) {
    # First start and detected reset bootstrap from a small recent slice.
    $taskRecords=@(Get-WinEvent -LogName $Channel -MaxEvents $MaxEvents | Sort-Object RecordId)
} else {
    $taskErrors=@()
    $taskRecords=@(Get-WinEvent -LogName $Channel -FilterXPath "*[System[EventRecordID > $After]]" -Oldest -MaxEvents $MaxEvents -ErrorAction SilentlyContinue -ErrorVariable taskErrors)
    foreach ($taskError in $taskErrors) {
        if ($taskError.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw $taskError }
    }
}
$taskCursor=$After
$taskCursorHash=$AfterHash
$taskWriter=[IO.StreamWriter]::new($taskOutput,$false,[Text.UTF8Encoding]::new($false))
try {
 foreach ($taskRecord in $taskRecords) {
  try {
    $taskRaw=$taskRecord.ToXml();[xml]$taskXml=$taskRaw
    $taskNs=[Xml.XmlNamespaceManager]::new($taskXml.NameTable)
    $taskNs.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
    $taskSystem=$taskXml.SelectSingleNode('/e:Event/e:System',$taskNs)
    $taskData=[ordered]@{};$taskPosition=0
    foreach ($taskNode in $taskXml.SelectNodes('/e:Event/e:EventData/e:Data',$taskNs)) {
        $taskName=$taskNode.GetAttribute('Name');if (-not $taskName) { $taskName="Data_$taskPosition" }
        if ($taskData.Contains($taskName)) { throw 'Duplicate event field' }
        $taskData[$taskName]=[string]$taskNode.InnerText;$taskPosition++
    }
    $taskEvent=[ordered]@{timestamp=$taskSystem.SelectSingleNode('e:TimeCreated',$taskNs).GetAttribute('SystemTime');host=[string]$taskSystem.SelectSingleNode('e:Computer',$taskNs).InnerText;channel=$Channel;provider=$taskSystem.SelectSingleNode('e:Provider',$taskNs).GetAttribute('Name');event_id=[int]$taskSystem.SelectSingleNode('e:EventID',$taskNs).InnerText;record_id=[long]$taskRecord.RecordId;event_data=$taskData;original_xml=$taskRaw;provenance=@{kind='real_host_collection';method='bounded cursor poll';collected_at=[DateTime]::UtcNow.ToString('o')}}
    $taskWriter.WriteLine(($taskEvent | ConvertTo-Json -Depth 20 -Compress))
    $taskCursor=[long]$taskRecord.RecordId
    $taskHasher=[Security.Cryptography.SHA256]::Create()
    try { $taskCursorHash=([BitConverter]::ToString($taskHasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($taskRaw)))).Replace('-','').ToLowerInvariant() } finally { $taskHasher.Dispose() }
  } finally { $taskRecord.Dispose() }
 }
} finally { $taskWriter.Dispose() }
[ordered]@{channel=$Channel;cursor=$taskCursor;cursor_hash=$taskCursorHash;count=$taskRecords.Count;gap=$taskGap;reset=$taskReset;oldest_available=$taskOldestId;latest_available=$taskLatestId;bootstrap=($After -eq 0)} | ConvertTo-Json -Compress
