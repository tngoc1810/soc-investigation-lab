<# Read existing System records. No auditing, service, firewall or endpoint changes. #>
[CmdletBinding()]
param([ValidateRange(1,200)][int]$MaxEvents=20,[Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskLocal=[System.IO.Path]::GetFullPath((Join-Path $taskRoot 'data/local'))+[System.IO.Path]::DirectorySeparatorChar
$taskOutput=[System.IO.Path]::GetFullPath($OutputPath)
if (-not $taskOutput.StartsWith($taskLocal,[System.StringComparison]::OrdinalIgnoreCase)) { throw 'Real host evidence must stay under ignored data/local/' }
if (Test-Path -LiteralPath $taskOutput) { throw 'Collection output already exists' }
[System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($taskOutput)) | Out-Null
$taskRecords=@(Get-WinEvent -LogName System -MaxEvents $MaxEvents -ErrorAction Stop)
$taskCollected=[DateTime]::UtcNow.ToString('o')
$taskWriter=[System.IO.StreamWriter]::new($taskOutput,$false,[System.Text.UTF8Encoding]::new($false))
try {
    foreach ($taskRecord in $taskRecords) {
        try {
            $taskXmlText=$taskRecord.ToXml()
            [xml]$taskXml=$taskXmlText
            $taskNs=[System.Xml.XmlNamespaceManager]::new($taskXml.NameTable)
            $taskNs.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
            $taskSystem=$taskXml.SelectSingleNode('/e:Event/e:System',$taskNs)
            $taskData=[ordered]@{}
            $taskPosition=0
            foreach ($taskNode in $taskXml.SelectNodes('/e:Event/e:EventData/e:Data',$taskNs)) {
                $taskName=$taskNode.GetAttribute('Name')
                if ([string]::IsNullOrWhiteSpace($taskName)) { $taskName="Data_$taskPosition" }
                if ($taskData.Contains($taskName)) { throw 'Duplicate event field' }
                $taskData[$taskName]=[string]$taskNode.InnerText
                $taskPosition++
            }
            $taskEvent=[ordered]@{timestamp=$taskSystem.SelectSingleNode('e:TimeCreated',$taskNs).GetAttribute('SystemTime');host=[string]$taskSystem.SelectSingleNode('e:Computer',$taskNs).InnerText;channel='System';provider=$taskSystem.SelectSingleNode('e:Provider',$taskNs).GetAttribute('Name');event_id=[int]$taskSystem.SelectSingleNode('e:EventID',$taskNs).InnerText;record_id=[long]$taskSystem.SelectSingleNode('e:EventRecordID',$taskNs).InnerText;event_data=$taskData;original_xml=$taskXmlText;provenance=@{kind='real_host_collection';collected_at=$taskCollected;method='Get-WinEvent System bounded read';note='Existing local operational records, no attack stimulus'}}
            $taskWriter.WriteLine(($taskEvent | ConvertTo-Json -Depth 20 -Compress))
        } finally { $taskRecord.Dispose() }
    }
} finally { $taskWriter.Dispose() }
Write-Output "Collected $($taskRecords.Count) existing System records under data/local/. Keep raw host evidence private."
