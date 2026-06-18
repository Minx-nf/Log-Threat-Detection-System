param(
    [string]$ServerUrl = "http://127.0.0.1:5000",
    [string]$PythonPath = "python",
    [string]$TaskName = "SOC-LAN-Log-Collector"
)

$CollectorPath = Join-Path $PSScriptRoot "windows_log_collector.py"
$Arguments = "`"$CollectorPath`" --server-url `"$ServerUrl`" --interval 15"

if (-not (Test-Path $CollectorPath)) {
    Write-Error "Collector script not found: $CollectorPath"
    exit 1
}

$Action = New-ScheduledTaskAction -Execute $PythonPath -Argument $Arguments
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Settings $Settings `
    -Force

Write-Host "Installed scheduled task: $TaskName"
Write-Host "Collector endpoint: $ServerUrl/api/logs"
