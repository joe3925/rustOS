$ErrorActionPreference = 'Stop'
Get-ChildItem -Directory | ForEach-Object {
    $dir = $_.FullName
    if (Test-Path (Join-Path $dir 'Cargo.toml')) {
        Push-Location $dir
        try {
            & cargo make build-driver
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        }
        finally {
            Pop-Location
        }
    }
}
