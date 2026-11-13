# SOCVision - start the backend API and the frontend together (Windows / PowerShell 5.1+).
#
#   .\start-dev.ps1            (or double-click start-dev.cmd)
#
# - Loads backend\.env into the environment (values are never printed)
# - Opens one window for the API (port 8000) and one for the web app (port 3000)
# - Waits until both answer, then opens http://localhost:3000
# Close the two windows to stop everything.
#
#   .\start-dev.ps1 -Check    only verifies the configuration, starts nothing

param([switch]$Check)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$backend = Join-Path $root "backend"
$frontend = Join-Path $root "frontend"

function Write-Step($text) { Write-Host "  $text" }
function Stop-WithError($text) {
    Write-Host ""
    Write-Host "  ERROR: $text" -ForegroundColor Red
    Write-Host ""
    exit 1
}

Write-Host ""
Write-Host "SOCVision - development start" -ForegroundColor Cyan

# 1. Load backend\.env (KEY=VALUE lines; anything else is ignored)
$envFile = Join-Path $backend ".env"
if (-not (Test-Path $envFile)) {
    Stop-WithError "backend\.env not found. Copy backend\.env.example to backend\.env and fill it in."
}
$loaded = @()
foreach ($line in Get-Content -Path $envFile -Encoding UTF8) {
    $line = $line.TrimStart([char]0xFEFF).Trim()
    if ($line -eq "" -or $line.StartsWith("#")) { continue }
    if ($line -notmatch '^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$') { continue }
    $name = $Matches[1]
    $value = $Matches[2].Trim()
    if ($value.StartsWith("[")) { continue }   # Python-style lists are not .env values
    if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
        $value = $value.Substring(1, $value.Length - 2)
    }
    if ($value -eq "") { continue }
    # A variable already set in this shell wins over the file.
    if (-not [Environment]::GetEnvironmentVariable($name, "Process")) {
        [Environment]::SetEnvironmentVariable($name, $value, "Process")
    }
    $loaded += $name
}
Write-Step ("Loaded from backend\.env: " + (($loaded | Sort-Object) -join ", "))

if (-not $env:JWT_SECRET_KEY) {
    Stop-WithError "JWT_SECRET_KEY is empty in backend\.env. Generate one with: python -c ""import secrets; print(secrets.token_urlsafe(32))"""
}

# 2. Prerequisites
foreach ($cmd in @("python", "npm")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { Stop-WithError "'$cmd' is not installed or not in PATH." }
}
if (-not (Test-Path (Join-Path $frontend "node_modules"))) {
    Write-Step "Installing frontend dependencies (first run)..."
    Push-Location $frontend
    try { npm install --no-fund --no-audit | Out-Null } finally { Pop-Location }
}
foreach ($port in @(8000, 3000)) {
    if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
        Stop-WithError "Port $port is already in use. Close the program using it (maybe a previous SOCVision window) and try again."
    }
}

if ($Check) {
    Write-Host ""
    Write-Host "Check OK: configuration loaded, ports 8000 and 3000 are free." -ForegroundColor Green
    Write-Host ""
    exit 0
}

# 3. Start both servers in their own windows (they inherit the variables loaded above)
Write-Step "Starting API      -> http://127.0.0.1:8000  (docs: /docs)"
Start-Process powershell -WorkingDirectory $backend -ArgumentList @(
    "-NoExit", "-Command",
    "`$host.UI.RawUI.WindowTitle = 'SOCVision API (port 8000)'; python -m uvicorn src.api.main:app --reload --port 8000"
)
Write-Step "Starting web app  -> http://localhost:3000"
Start-Process powershell -WorkingDirectory $frontend -ArgumentList @(
    "-NoExit", "-Command",
    "`$host.UI.RawUI.WindowTitle = 'SOCVision web (port 3000)'; npm run dev"
)

# 4. Wait until both answer
function Wait-Http($url, $label) {
    for ($i = 0; $i -lt 90; $i++) {
        try {
            $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2
            if ($r.StatusCode -eq 200) { Write-Step "$label is up"; return $true }
        } catch { }
        Start-Sleep -Seconds 1
    }
    Write-Host "  $label did not answer after 90 s - check its window for errors." -ForegroundColor Yellow
    return $false
}
$apiUp = Wait-Http "http://127.0.0.1:8000/api/health" "API"
$webUp = Wait-Http "http://localhost:3000/login" "Web app"

# 5. Optional services
try {
    Invoke-WebRequest -Uri "http://localhost:11434/api/tags" -UseBasicParsing -TimeoutSec 2 | Out-Null
    Write-Step "Ollama is reachable (AI analysis available)"
} catch {
    Write-Host "  Ollama is not running: alerts still work, AI analysis and reports need it (start the Ollama app)." -ForegroundColor Yellow
}

if ($apiUp -and $webUp) {
    Start-Process "http://localhost:3000"
    Write-Host ""
    Write-Host "Ready. Close the two SOCVision windows to stop." -ForegroundColor Green
}
Write-Host ""
