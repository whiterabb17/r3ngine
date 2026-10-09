$ErrorActionPreference = "Stop"
$Node = if ($env:NODE) { $env:NODE } else { "node" }
& $Node (Join-Path $PSScriptRoot "install-mcp.mjs") @args
exit $LASTEXITCODE
