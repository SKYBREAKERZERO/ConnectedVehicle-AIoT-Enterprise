param([string]$Config = ".runtime-reports/local-monitor-config.json")
$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$configPath = Join-Path $projectRoot $Config
if (-not (Test-Path -LiteralPath $configPath)) { throw "Create the local monitor configuration first." }
$statePath = Join-Path $projectRoot ".runtime-reports/observability"
New-Item -ItemType Directory -Force -Path $statePath | Out-Null
$pidPath = Join-Path $statePath "collector.pid"
if (Test-Path -LiteralPath $pidPath) {
    $collectorId = [int](Get-Content -LiteralPath $pidPath)
    $existing = Get-CimInstance Win32_Process -Filter "ProcessId = $collectorId"
    if ($existing -and $existing.CommandLine -like "*scripts.local_monitor*collect*") {
        throw "Collector already running as process $collectorId."
    }
}
$pythonPath = Join-Path $projectRoot ".venv/Scripts/python.exe"
$arguments = '-m scripts.local_monitor collect --directory "{0}" --config "{1}"' -f $statePath, $configPath
$collector = Start-Process -FilePath $pythonPath -ArgumentList $arguments -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $statePath "collector.stdout.log") -RedirectStandardError (Join-Path $statePath "collector.stderr.log")
$collector.Id | Set-Content -LiteralPath $pidPath
docker compose -p vehicle-observability -f (Join-Path $projectRoot "infra/observability/compose.yml") up -d
if ($LASTEXITCODE -ne 0) { throw "Local observability startup failed." }
Write-Host "Local dashboards: http://localhost:19091 and http://localhost:19093"
