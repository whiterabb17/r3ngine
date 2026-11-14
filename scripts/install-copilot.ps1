$ErrorActionPreference = "Stop"
$Node = if ($env:NODE) { $env:NODE } else { "node" }
& $Node (Join-Path $PSScriptRoot "install-copilot.mjs") @args
exit $LASTEXITCODE
