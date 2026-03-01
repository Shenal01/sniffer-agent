param(
    [string]$Mode = "capture"
)

$AgentExe = ".\build\Release\UnifiedSnifferAgent.exe"
if (-Not (Test-Path $AgentExe)) {
    Write-Host "Agent not found at $AgentExe! Please run Build-Agent.ps1 first."
    exit 1
}

Write-Host "Running Unified Sniffer Agent in $Mode mode..."
& $AgentExe --mode=$Mode
