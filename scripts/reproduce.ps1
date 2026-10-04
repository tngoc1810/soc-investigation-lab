<# Rebuild all four independent case bundles on Windows, without running attack commands. #>
[CmdletBinding()]
param([ValidatePattern('^[A-Za-z0-9_-]+$')][string]$RunId = ('run-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')))
$ErrorActionPreference = 'Stop'
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $taskCases = @(
        @{ id='case-001'; title='Mshta and scheduled-task activity'; source='public-mshta-task'; kind='Public EVTX'; verdict='Escalate'; report='cases/001-mshta-scheduled-task/report.md' },
        @{ id='case-002'; title='Failed logon burst and explicit-credential supplement'; source='public-auth-guessing'; kind='Public EVTX'; verdict='Escalate; success unproven'; report='cases/002-authentication/report.md' },
        @{ id='case-003'; title='PowerShell code or quoted data?'; source='public-powershell-string'; kind='Public EVTX'; verdict='Hold; execution unproven'; report='cases/003-powershell-string/report.md' },
        @{ id='case-004'; title='Context tuning with an auditable allowlist'; source='context-fixture'; kind='Synthetic experiment'; verdict='One expected activity; variants reviewed'; report='cases/004-context-tuning/report.md' }
    )
    $taskCatalog = Get-Content data/catalog.json -Raw | ConvertFrom-Json
    $taskIndexCases = @()
    foreach ($taskCase in $taskCases) {
        $taskBundle = "output/portfolio/$RunId/$($taskCase.id)"
        if ($taskCase.source -eq 'context-fixture') { $taskJsonl = 'data/fixtures/context-tuning.jsonl' }
        else {
            ./scripts/fetch_sample.ps1 -Sample $taskCase.source
            $taskEvtx = 'data/raw/public/' + $taskCatalog.($taskCase.source).filename
            $taskJsonl = "data/raw/public/$($taskCase.id)-$RunId.jsonl"
            ./scripts/export_evtx.ps1 -InputPath $taskEvtx -OutputPath $taskJsonl
        }
        python -m soclab ingest $taskJsonl --db "$taskBundle/evidence.sqlite"
        if ($LASTEXITCODE -ne 0) { throw 'Ingestion failed' }
        if ($taskCase.id -eq 'case-004') {
            python -m soclab analyze --db "$taskBundle/evidence.sqlite" --out "$taskBundle/baseline"
            if ($LASTEXITCODE -ne 0) { throw 'Baseline analysis failed' }
            python -m soclab analyze --db "$taskBundle/evidence.sqlite" --out "$taskBundle/analysis" --context rules/context-lab.json
        } else {
            python -m soclab analyze --db "$taskBundle/evidence.sqlite" --out "$taskBundle/analysis"
        }
        if ($LASTEXITCODE -ne 0) { throw 'Analysis failed' }
        $taskIndexCases += @{ id=$taskCase.id; title=$taskCase.title; kind=$taskCase.kind; verdict=$taskCase.verdict; report=$taskCase.report; db="$taskBundle/evidence.sqlite"; analysis="$taskBundle/analysis" }
    }
    # Supplement is intentionally independent from case-002's primary evidence.
    ./scripts/fetch_sample.ps1 -Sample public-explicit-credentials
    $taskSupplement = "data/raw/public/explicit-$RunId.jsonl"
    ./scripts/export_evtx.ps1 -InputPath data/raw/public/auth-spray.evtx -OutputPath $taskSupplement
    python -m soclab ingest $taskSupplement --db "output/portfolio/$RunId/supplement/evidence.sqlite"
    if ($LASTEXITCODE -ne 0) { throw 'Supplement ingestion failed' }
    python -m soclab analyze --db "output/portfolio/$RunId/supplement/evidence.sqlite" --out "output/portfolio/$RunId/supplement/analysis"
    if ($LASTEXITCODE -ne 0) { throw 'Supplement analysis failed' }
    $taskIndex = @{ run_id=$RunId; cases=$taskIndexCases; note='Independent datasets; totals do not describe a single incident.' }
    [System.IO.File]::WriteAllText((Join-Path (Get-Location).Path 'output/portfolio/index.json'), ($taskIndex | ConvertTo-Json -Depth 10), [System.Text.UTF8Encoding]::new($false))
    Write-Output 'Portfolio rebuilt. Start: python -m soclab serve'
} finally { Pop-Location }
