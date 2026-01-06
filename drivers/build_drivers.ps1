$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    cargo build
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}
