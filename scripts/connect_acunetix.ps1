# Strict mode
Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ==================================================
# r3ngine - Connect Acunetix Container to r3ngine Network
# ==================================================
#
# Finds running Docker containers matching 'acunetix'
# and connects them to the r3ngine network.
#
# Usage:
#   .\scripts\connect_acunetix.ps1 [-Network <name>] [-Container <name>] [-DryRun]
# ==================================================

param (
    [string]$Network = "",
    [string]$Container = "acunetix",
    [switch]$DryRun = $false
)

Write-Output "=================================================="
Write-Output "      r3ngine - Connect Acunetix Container"
Write-Output "=================================================="

# Verify docker is installed
if (!(Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "[!] ERROR: docker command not found. Please install Docker first."
    exit 1
}

# Discover network
$targetNetwork = ""
if ($Network) {
    $targetNetwork = $Network
} else {
    Write-Output "[*] Auto-discovering r3ngine network..."
    $networks = docker network ls --format "{{.Name}}"
    $discovered = @()
    if ($networks) {
        $discovered = $networks | Where-Object { $_ -like "*r3ngine*" }
    }
    
    if ($discovered) {
        if ($discovered -is [array]) {
            $targetNetwork = $discovered[0]
        } else {
            $targetNetwork = $discovered
        }
        Write-Output "[+] Discovered network: $targetNetwork"
    } else {
        # Fallback network name
        $targetNetwork = "r3ngine_network"
        Write-Output "[!] No matching r3ngine network discovered. Using fallback: $targetNetwork"
    }
}

# Find running containers matching container filter
Write-Output "[*] Searching for running containers matching '$Container'..."
$runningContainers = docker ps --filter "status=running" --format "{{.Names}}"
$matched = @()
if ($runningContainers) {
    $matched = $runningContainers | Where-Object { $_ -like "*$Container*" }
}

$hasMatched = $false
if ($matched) {
    $hasMatched = $true
}

if (!$hasMatched) {
    Write-Output "[!] No running containers found matching '$Container'."
    Write-Output "[*] Here are all currently running containers:"
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    exit 0
}

# Loop through found containers and connect them if they aren't already
foreach ($containerName in $matched) {
    if (!$containerName) {
        continue
    }
    Write-Output "[*] Checking container: $containerName"
    
    # Check if network exists
    docker network inspect $targetNetwork | Out-Null
    $networkExists = ($LASTEXITCODE -eq 0)

    if (!$networkExists) {
        if ($DryRun) {
            Write-Output "[DRY-RUN] Target network '$targetNetwork' does not exist. Would attempt to connect anyway."
        } else {
            Write-Warning "[!] ERROR: Target network '$targetNetwork' does not exist. Cannot connect."
            continue
        }
    }

    # Check if already connected
    $networkJson = docker inspect $containerName --format '{{json .NetworkSettings.Networks}}'
    $isConnected = $false
    if ($networkJson) {
        if ($networkJson -like "*`"$targetNetwork`"*") {
            $isConnected = $true
        }
    }

    if ($isConnected) {
        Write-Output "[+] Container '$containerName' is already connected to network '$targetNetwork'."
    } else {
        if ($DryRun) {
            Write-Output "[DRY-RUN] Would connect container '$containerName' to network '$targetNetwork'."
            Write-Output "[DRY-RUN] Command: docker network connect $targetNetwork $containerName"
        } else {
            Write-Output "[*] Connecting '$containerName' to '$targetNetwork'..."
            docker network connect $targetNetwork $containerName
            if ($LASTEXITCODE -eq 0) {
                Write-Output "[+] Successfully connected '$containerName' to '$targetNetwork'."
            } else {
                Write-Warning "[!] ERROR: Failed to connect '$containerName' to '$targetNetwork'."
            }
        }
    }
}

Write-Output ""
Write-Output "[+] Done!"
