# start-daemon.ps1 — bootstrap the CIDAS daemon on Windows.
#
# Mirrors start-daemon.sh: creates daemon\.venv if absent, installs the
# daemon package in editable mode, then starts uvicorn as a background
# process and waits for /api/v1/health to respond.
#
# The venv's uvicorn.exe is invoked by absolute path; we deliberately do
# not rely on Activate.ps1 having modified $env:Path for Start-Process,
# because Start-Process snapshots the parent's PATH at call time and the
# behaviour around current-session-only changes is inconsistent across
# PowerShell versions.

#Requires -Version 5.1
$ErrorActionPreference = "Stop"

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path (Join-Path $ScriptDir "..")
$DaemonDir   = Join-Path $ProjectRoot "daemon"
$VenvDir     = Join-Path $DaemonDir ".venv"
$PidFile     = Join-Path $ProjectRoot ".cidas.pid"
$Port        = if ($env:DAEMON_PORT) { $env:DAEMON_PORT } else { "7355" }
$Host_       = if ($env:DAEMON_HOST) { $env:DAEMON_HOST } else { "127.0.0.1" }
$LogLevel    = if ($env:LOG_LEVEL)   { $env:LOG_LEVEL   } else { "info" }

# Activate.ps1 isn't strictly needed (we use the venv binaries by full path)
# but loading .env keeps parity with start-daemon.sh's `set -a; source .env`.
$EnvFile = Join-Path $ProjectRoot ".env"
if (Test-Path -LiteralPath $EnvFile) {
    Get-Content -LiteralPath $EnvFile | Where-Object { $_ -match "^\s*[A-Za-z_][A-Za-z0-9_]*\s*=" } | ForEach-Object {
        $parts = $_ -split "=", 2
        $key = $parts[0].Trim()
        $val = $parts[1].Trim().Trim('"').Trim("'")
        [Environment]::SetEnvironmentVariable($key, $val, "Process")
    }
    Write-Host "`[CIDAS`] Loaded $EnvFile"
}

# Cheap port-occupancy check via .NET — avoids depending on lsof/Get-NetTCPConnection
# being present (the latter ships only on Windows 8+/Server 2012+ but not on
# every PowerShell Core install).
function Test-PortListening([string]$bindHost, [int]$port) {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($bindHost, $port, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne(200)
        if ($ok -and $client.Connected) { $client.Close(); return $true }
        $client.Close()
    } catch { }
    return $false
}

if (Test-PortListening $Host_ ([int]$Port)) {
    Write-Host "`[CIDAS`] Daemon already running on port $Port."
    exit 0
}

# Create venv if absent.
if (-not (Test-Path -LiteralPath $VenvDir)) {
    Write-Host "`[CIDAS`] Creating Python virtual environment in $VenvDir..."
    & python -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Error "`[CIDAS`] python -m venv failed (exit $LASTEXITCODE). Is Python 3.10+ on PATH?"
        exit 1
    }
    $venvPip = Join-Path $VenvDir "Scripts\pip.exe"
    & $venvPip install --quiet --upgrade pip
    & $venvPip install --quiet -e "$DaemonDir[dev]"
    if ($LASTEXITCODE -ne 0) {
        Write-Error "`[CIDAS`] pip install failed (exit $LASTEXITCODE)."
        exit $LASTEXITCODE
    }
}

$VenvUvicorn = Join-Path $VenvDir "Scripts\uvicorn.exe"
if (-not (Test-Path -LiteralPath $VenvUvicorn)) {
    Write-Error "`[CIDAS`] uvicorn.exe missing at $VenvUvicorn - the venv may be corrupt. Delete $VenvDir and rerun."
    exit 1
}

Write-Host "`[CIDAS`] Starting daemon on $($Host_):$Port ..."
$proc = Start-Process -FilePath $VenvUvicorn `
    -ArgumentList @(
        "daemon.main:app",
        "--host", $Host_,
        "--port", $Port,
        "--log-level", $LogLevel,
        "--app-dir", $ProjectRoot
    ) `
    -WindowStyle Hidden `
    -PassThru

$proc.Id | Out-File -LiteralPath $PidFile -Encoding ASCII
Write-Host "`[CIDAS`] Daemon PID $($proc.Id) written to $PidFile"

# Poll the health endpoint for up to 30 seconds, same as the bash version.
Write-Host "`[CIDAS`] Waiting for daemon to be ready..."
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    try {
        $resp = Invoke-WebRequest -Uri "http://$($Host_):$Port/api/v1/health" -UseBasicParsing -TimeoutSec 2
        if ($resp.StatusCode -eq 200) { $ready = $true; break }
    } catch { }

    if ($proc.HasExited) {
        Write-Error "`[CIDAS`] Daemon process exited unexpectedly (code $($proc.ExitCode))."
        exit 1
    }
    Start-Sleep -Seconds 1
}

if ($ready) {
    Write-Host '[CIDAS] Daemon is ready.'
} else {
    Write-Warning '[CIDAS] Daemon did not respond to /api/v1/health within 30s - check logs.'
}

Write-Host "`[CIDAS`] Swagger UI -> http://$($Host_):$Port/docs"
