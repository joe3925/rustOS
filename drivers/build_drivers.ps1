$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    cargo build --target "targets/x86_64-rustos-pe.json" 
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}
