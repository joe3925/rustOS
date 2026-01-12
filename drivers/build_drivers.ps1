$ErrorActionPreference = 'Stop'

param(
    [switch]$Release
)

Push-Location $PSScriptRoot
try {
    $args = @("--workspace")
    if ($Release) {
        $args += "--release"
    }

    cargo build @args
} finally {
    Pop-Location
}
