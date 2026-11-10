<#
Opens a temporary public HTTPS link to the running system, so other people can use it from their own
phone or laptop (for example the panel at the defence). Face ID works over the link because it is HTTPS.

Usage, from the repository root:
    powershell -ExecutionPolicy Bypass -File demo\start-public-demo.ps1                   # start
    powershell -ExecutionPolicy Bypass -File demo\start-public-demo.ps1 -WithAttendance   # also the attendance demo
    powershell -ExecutionPolicy Bypass -File demo\start-public-demo.ps1 -Stop             # close the link

What it does: starts the system if needed, opens a Cloudflare quick tunnel (a free https://....trycloudflare.com
address that changes every time), points the backend's email links at that address for as long as the link is
open, and prints the link (also copied to the clipboard). backend\.env.docker is never edited: the public
settings live in demo\public-demo.compose.yml and -Stop removes them.

The laptop must stay on, awake and online while the link is in use. Anyone with the link reaches the sign-in
page (they still need an account and the second factor), so run -Stop when the demonstration is over.
Full instructions: demo\PUBLIC_DEMO.md
#>
param([switch]$Stop, [switch]$WithAttendance)

$LocalApp = "http://127.0.0.1:5173"
$LocalBackend = "http://127.0.0.1:8000"
$LocalAttendance = "http://127.0.0.1:9000"
$CloudflaredDownload = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"

$root = Split-Path -Parent $PSScriptRoot
$toolsDir = Join-Path $PSScriptRoot "tools"            # git-ignored: downloaded cloudflared, logs, state
$stateFile = Join-Path $toolsDir "public-demo.json"
$publicCompose = Join-Path $PSScriptRoot "public-demo.compose.yml"
$ProgressPreference = "SilentlyContinue"               # Windows PowerShell downloads are very slow with a progress bar
Set-Location $root
New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null

function Say($text, $colour = "Gray") { Write-Host $text -ForegroundColor $colour }

function Get-ComposeArgs([bool]$public) {
    # The same files plain "docker compose" would use, plus the public settings while the link is open.
    $files = @("-f", (Join-Path $root "docker-compose.yml"))
    $override = Join-Path $root "docker-compose.override.yml"
    if (Test-Path $override) { $files += @("-f", $override) }
    if ($public) { $files += @("-f", $publicCompose) }
    return , $files
}

function Wait-Url($url, $seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        try {
            Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 | Out-Null
            return $true
        } catch {
            Start-Sleep -Seconds 3
        }
    }
    return $false
}

function Set-BackendMode([bool]$public, $publicUrl) {
    # Recreates only the backend container (no rebuild) with or without the public settings.
    if ($public) { $env:PUBLIC_DEMO_URL = $publicUrl } else { Remove-Item Env:PUBLIC_DEMO_URL -ErrorAction SilentlyContinue }
    $composeArgs = Get-ComposeArgs $public
    & docker compose @composeArgs up -d --no-build backend 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { return $false }
    return (Wait-Url "$LocalBackend/health" 240)
}

function Read-Log($path) {
    # The tunnel keeps its log open, so read it without locking it.
    if (-not (Test-Path $path)) { return "" }
    $stream = [System.IO.File]::Open($path, "Open", "Read", "ReadWrite")
    try { return (New-Object System.IO.StreamReader($stream)).ReadToEnd() } finally { $stream.Dispose() }
}

function Get-Cloudflared {
    $onPath = Get-Command cloudflared -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    $exe = Join-Path $toolsDir "cloudflared.exe"
    if (-not (Test-Path $exe)) {
        Say "Downloading cloudflared (Cloudflare's official tunnel program, about 60 MB, once) ..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        try {
            Invoke-WebRequest -Uri $CloudflaredDownload -OutFile $exe -UseBasicParsing
        } catch {
            Remove-Item $exe -ErrorAction SilentlyContinue
            Say "Download failed: $($_.Exception.Message)" Red
            Say "Check the internet connection, or install it yourself: winget install --id Cloudflare.cloudflared" Yellow
            return $null
        }
    }
    $signature = Get-AuthenticodeSignature $exe
    if ($signature.Status -ne "Valid" -or $signature.SignerCertificate.Subject -notmatch "Cloudflare") {
        Say "demo\tools\cloudflared.exe is not validly signed by Cloudflare; deleting it. Run the script again." Red
        Remove-Item $exe -ErrorAction SilentlyContinue
        return $null
    }
    return $exe
}

function Start-Tunnel($exe, $localUrl, $name) {
    $log = Join-Path $toolsDir "$name.log"
    Remove-Item $log, "$log.out" -ErrorAction SilentlyContinue
    # --protocol http2: connect over ordinary HTTPS (TCP 443). The default, QUIC, uses UDP, which many school and
    # venue networks block; the tunnel then never connects and the link answers with error 530.
    $tunnelArgs = @("tunnel", "--no-autoupdate", "--protocol", "http2", "--url", $localUrl)
    $process = Start-Process -FilePath $exe -ArgumentList $tunnelArgs `
        -RedirectStandardError $log -RedirectStandardOutput "$log.out" -WindowStyle Hidden -PassThru
    # cloudflared prints its address before it has connected, so wait for both: the address, and the
    # "Registered tunnel connection" line that means Cloudflare can actually reach this laptop.
    $url = $null
    $deadline = (Get-Date).AddSeconds(75)
    while ((Get-Date) -lt $deadline -and -not $process.HasExited) {
        $text = Read-Log $log
        $match = [regex]::Match($text, "https://[a-z0-9-]+\.trycloudflare\.com")
        if ($match.Success) { $url = $match.Value }
        if ($url -and $text -match "Registered tunnel connection") {
            return @{ Pid = $process.Id; Url = $url; Log = $log }
        }
        Start-Sleep -Seconds 1
    }
    Stop-Process -Id $process.Id -ErrorAction SilentlyContinue
    $text = Read-Log $log
    if ($url -and $text -match "7844") {
        Say "This network blocks Cloudflare's tunnel port (7844), so the link cannot work here." Red
        Say "Switch the laptop to another network (a phone hotspot works) and run the script again," Yellow
        Say "or present from this laptop at $LocalApp." Yellow
    } else {
        Say "The tunnel did not connect. Last lines of $log :" Red
        $text -split "`n" | Select-Object -Last 6 | ForEach-Object { Say "  $_" }
    }
    return $null
}

function Stop-Tunnels {
    if (-not (Test-Path $stateFile)) { return }
    $state = Get-Content $stateFile -Raw | ConvertFrom-Json
    foreach ($tunnelPid in @($state.pids)) { Stop-Process -Id $tunnelPid -ErrorAction SilentlyContinue }
    Remove-Item $stateFile -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------- stop

if ($Stop) {
    Say "Closing the public link ..."
    Stop-Tunnels
    Say "Putting the backend back to its normal settings (about a minute) ..."
    if (Set-BackendMode $false $null) {
        Say "Public link closed. The system is back on $LocalApp only." Green
        exit 0
    }
    Say "The backend did not come back in time. Check: docker compose logs backend" Red
    exit 1
}

# ---------------------------------------------------------------- start

if (Test-Path $stateFile) {
    $state = Get-Content $stateFile -Raw | ConvertFrom-Json
    $alive = @($state.pids | Where-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue })
    if ($alive.Count -gt 0) {
        Say "A public link is already open: $($state.url)" Yellow
        Say "To open a new one, close it first:  powershell -ExecutionPolicy Bypass -File demo\start-public-demo.ps1 -Stop"
        exit 0
    }
    Remove-Item $stateFile -ErrorAction SilentlyContinue
}

Say "1/5  Checking Docker ..."
docker info 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Say "Docker is not running. Start Docker Desktop, wait until it says 'running', then try again." Red; exit 1 }

Say "2/5  Starting the system (no rebuild) ..."
$composeArgs = Get-ComposeArgs $false
& docker compose @composeArgs up -d --no-build 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Say "docker compose failed. If this is a fresh copy, build once first: docker compose up -d --build" Red; exit 1 }
if (-not (Wait-Url "$LocalBackend/health" 240) -or -not (Wait-Url $LocalApp 60)) {
    Say "The system did not answer in time. Check: docker compose ps   and   docker compose logs backend" Red; exit 1
}

Say "3/5  Opening the public HTTPS link ..."
$cloudflared = Get-Cloudflared
if (-not $cloudflared) { exit 1 }
$app = Start-Tunnel $cloudflared $LocalApp "tunnel-app"
if (-not $app) { Say "No link was opened and nothing was changed." ; exit 1 }
$pids = @($app.Pid)

Say "4/5  Pointing email links at $($app.Url) (the backend restarts, about a minute) ..."
if (-not (Set-BackendMode $true $app.Url)) {
    Stop-Process -Id $app.Pid -ErrorAction SilentlyContinue
    Set-BackendMode $false $null | Out-Null
    Say "The backend did not restart in time. Nothing was left open. Check: docker compose logs backend" Red; exit 1
}

$attendance = $null
if ($WithAttendance) {
    if (Wait-Url $LocalAttendance 5) {
        $attendance = Start-Tunnel $cloudflared $LocalAttendance "tunnel-attendance"
        if ($attendance) { $pids += $attendance.Pid }
    } else {
        Say "The attendance demo is not running; start it first: powershell -ExecutionPolicy Bypass -File demo\start-demo.ps1" Yellow
    }
}

@{ url = $app.Url; attendance = $(if ($attendance) { $attendance.Url } else { $null }); pids = $pids;
   started = (Get-Date).ToString("s") } | ConvertTo-Json | Set-Content -Path $stateFile -Encoding ascii

Say "5/5  Checking the link works from the internet (new addresses can take up to a minute) ..."
$reachable = Wait-Url "$($app.Url)/api/v1/health" 120
try { Set-Clipboard -Value $app.Url } catch { }

Write-Host ""
Say "============================================================" Green
Say "  Public link (copied to the clipboard):" Green
Say "    $($app.Url)" Green
if ($attendance) { Say "  Attendance demo:  $($attendance.Url)" Green }
Say "============================================================" Green
if (-not $reachable) {
    Say "The link has not answered yet from the internet. Wait a minute and open it; if it still fails," Yellow
    Say "this network may block tunnels: try a phone hotspot, or present from this laptop ($LocalApp)." Yellow
}
Say ""
Say "How others use it:"
Say "  1. Open the link on their phone or laptop (any browser; no install)."
Say "  2. Sign in with one of your demo accounts. The second factor is the emailed code, which goes to"
Say "     YOUR inbox (the demo accounts use your email): read it out to them. Face ID works only for an"
Say "     account whose face is enrolled; the camera works because the link is HTTPS."
Say "  3. Everything they do appears live in your dashboard, like any other user."
Say ""
Say "Keep this laptop on, awake and online. The link changes every time you run this script."
Say "When finished:  powershell -ExecutionPolicy Bypass -File demo\start-public-demo.ps1 -Stop" Yellow
