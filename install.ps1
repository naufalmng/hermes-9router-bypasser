# h9b — Windows bootstrap. Nothing is installed; the exe is fetched to temp,
# run, and deleted. Only %USERPROFILE%\.h9b\config.json (the licence) survives.
#
#   iwr -useb https://raw.githubusercontent.com/naufalmng/hermes-9router-bypasser/master/install.ps1 | iex
#
# With arguments (iex cannot forward them, so pass them through the environment):
#
#   $env:H9B_ARGS="activate H9B-XXXXX-XXXXX-XXXXX-XXX"; iwr -useb <url> | iex
#   $env:H9B_ARGS="apply";                              iwr -useb <url> | iex
#
# Or dot-source it with real parameters:
#
#   & ([scriptblock]::Create((iwr -useb <url>).Content)) activate H9B-XXXX-...
#
# This script only *fetches*. The binary and the recipes both come from the h9b
# server; the repository holds no patch data.

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$Mirror   = if ($env:H9B_MIRROR) { $env:H9B_MIRROR } else { 'https://h9b.apizen.my.id/dl' }
$ArgsStr  = if ($env:H9B_ARGS)   { $env:H9B_ARGS }   else { 'apply' }
$KeepExe  = $env:H9B_KEEP -eq '1'

# --- pick the asset -----------------------------------------------------------
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { 'amd64' }
  'ARM64' { 'arm64' }
  'x86'   { throw 'h9b: 32-bit Windows is not supported' }
  default { throw "h9b: unsupported architecture $($env:PROCESSOR_ARCHITECTURE)" }
}
$asset = "h9b-windows-$arch.exe"

Write-Host "  fetching $asset" -ForegroundColor DarkGray

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("h9b-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$exe = Join-Path $tmp 'h9b.exe'

try {
  # TLS 1.2 explicitly: Windows PowerShell 5.1 still defaults to TLS 1.0 on some
  # builds and the handshake then fails with an unhelpful "underlying connection
  # was closed".
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

  $url = "$Mirror/$asset"
  try {
    Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing -TimeoutSec 180
  } catch {
    # GitHub releases are the fallback only. Its asset CDN stalls on some
    # consumer links, which is why our own mirror is tried first.
    Write-Host '  mirror failed, trying releases' -ForegroundColor DarkYellow
    $url = "https://github.com/naufalmng/hermes-9router-bypasser/releases/latest/download/$asset"
    Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing -TimeoutSec 180
  }

  # --- checksum ---------------------------------------------------------------
  try {
    $sumsPath = Join-Path $tmp 'SHA256SUMS'
    Invoke-WebRequest -Uri "$Mirror/SHA256SUMS" -OutFile $sumsPath -UseBasicParsing -TimeoutSec 60
    $line = Select-String -Path $sumsPath -Pattern ([regex]::Escape(" $asset")) -SimpleMatch |
            Select-Object -First 1
    if ($line) {
      $want = ($line.Line -split '\s+')[0].ToLower()
      $got  = (Get-FileHash -Path $exe -Algorithm SHA256).Hash.ToLower()
      if ($want -ne $got) {
        throw "checksum mismatch for $asset (expected $want, got $got) — refusing to run"
      }
      Write-Host '  checksum ok' -ForegroundColor DarkGray
    }
  } catch [System.Management.Automation.RuntimeException] {
    throw
  } catch {
    Write-Host '  no checksum available, continuing' -ForegroundColor DarkYellow
  }

  # --- run --------------------------------------------------------------------
  # Unblock-File: the file came off the internet, and without this the zone
  # identifier makes execution fail on machines with a strict policy.
  Unblock-File -Path $exe -ErrorAction SilentlyContinue

  $argv = $ArgsStr -split '\s+' | Where-Object { $_ -ne '' }
  Write-Host "  running: h9b $ArgsStr" -ForegroundColor DarkGray
  Write-Host ''

  & $exe @argv
  $rc = $LASTEXITCODE
  exit $rc
}
finally {
  if (-not $KeepExe) {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  } else {
    Write-Host "  kept: $exe" -ForegroundColor DarkGray
  }
}
