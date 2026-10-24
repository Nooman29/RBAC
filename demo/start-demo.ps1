<#
Starts the School Meal Attendance demo module in one step.

Usage, from the repository root:
    powershell -ExecutionPolicy Bypass -File demo\start-demo.ps1         # start
    powershell -ExecutionPolicy Bypass -File demo\start-demo.ps1 -Stop   # stop

Reads DSFS_CLIENT_ID and DSFS_CLIENT_SECRET from demo\.env, which is git-ignored.
Uses 127.0.0.1 rather than localhost: on Windows, localhost can resolve to IPv6 (::1)
while Docker publishes the ports on IPv4.
#>
param([switch]$Stop)

$BackendUrl = "http://127.0.0.1:8000"
$DemoUrl = "http://127.0.0.1:9000"

$root = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $PSScriptRoot ".env"
$composeFile = Join-Path $PSScriptRoot "docker-compose.yml"
Set-Location $root

if (-not (Test-Path $envFile)) {
    Write-Host "Missing demo\.env. Create it with two lines:" -ForegroundColor Yellow
    Write-Host "  DSFS_CLIENT_ID=dsfs_cl_..."
    Write-Host "  DSFS_CLIENT_SECRET=dsfs_sk_..."
    Write-Host "Get both from the RBAC dashboard: Integrations -> Attendance demo -> Rotate secret."
    exit 1
}

if ($Stop) {
    docker compose --env-file $envFile -f $composeFile down
    Write-Host "Demo stopped." -ForegroundColor Green
    exit 0
}

Write-Host "Checking the RBAC backend at $BackendUrl ..."
try {
    Invoke-RestMethod -Uri "$BackendUrl/health" -TimeoutSec 5 | Out-Null
} catch {
    Write-Host "The RBAC backend is not running. Start it first: docker compose up -d" -ForegroundColor Red
    exit 1
}

Write-Host "Starting the attendance demo ..."
docker compose --env-file $envFile -f $composeFile up -d
if ($LASTEXITCODE -ne 0) {
    Write-Host "docker compose failed; see the messages above." -ForegroundColor Red
    exit 1
}

Write-Host "Waiting for $DemoUrl (the first start installs packages; up to 2 minutes) ..."
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    try {
        Invoke-WebRequest -Uri $DemoUrl -UseBasicParsing -TimeoutSec 3 | Out-Null
        $ready = $true
        break
    } catch {
        Start-Sleep -Seconds 2
    }
}

if (-not $ready) {
    Write-Host "The demo did not answer in time. See the logs:" -ForegroundColor Red
    Write-Host "  docker compose --env-file demo/.env -f demo/docker-compose.yml logs"
    exit 1
}

Write-Host "Demo is up: $DemoUrl" -ForegroundColor Green
Write-Host "Sign in as demo_teacher, demo_teacher_b, demo_parent or demo_finance."
Start-Process $DemoUrl