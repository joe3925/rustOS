Get-ChildItem -Directory | ForEach-Object {
     if (Test-Path "$($_.FullName)\Cargo.toml") {
         Push-Location $_.FullName
        cargo make build-driver
         Pop-Location
     }
 }