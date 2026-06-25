#!/bin/bash

# ==================================================
# r3ngine – Connect Acunetix Container to r3ngine Network
# ==================================================
#
# Finds running Docker containers matching 'acunetix'
# and connects them to the r3ngine network.
#
# Usage:
#   ./scripts/connect_acunetix.sh [options]
#
# Options:
#   --network <name>    Target docker network (default: auto-discover matching '*r3ngine*')
#   --container <name>  Container name substring filter (default: "acunetix")
#   --dry-run           Show actions without executing them
#   -h, --help          Show this help message
# ==================================================

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# ── Defaults ────────────────────────────────────────
NETWORK_ARG=""
CONTAINER_FILTER="acunetix"
DRY_RUN=false

# ── Argument parsing ─────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --network)
            NETWORK_ARG="$2"
            shift 2
            ;;
        --container)
            CONTAINER_FILTER="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --network <name>    Target docker network (default: auto-discover)"
            echo "  --container <name>  Container name substring filter (default: 'acunetix')"
            echo "  --dry-run           Show actions without executing them"
            echo "  -h, --help          Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Usage: $0 [--network <name>] [--container <name>] [--dry-run]"
            exit 1
            ;;
    esac
done

# ── Banner ───────────────────────────────────────────
echo -e "${BLUE}=================================================="
echo "      r3ngine – Connect Acunetix Container"
echo -e "==================================================${NC}\n"

# Verify docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}ERROR: docker command not found. Please install Docker first.${NC}"
    exit 1
fi

# Discover network
TARGET_NETWORK=""
if [ -n "$NETWORK_ARG" ]; then
    TARGET_NETWORK="$NETWORK_ARG"
    # Verify the specified network exists
    if ! docker network inspect "$TARGET_NETWORK" &> /dev/null; then
        echo -e "${YELLOW}WARNING: Network '$TARGET_NETWORK' not found in docker network ls.${NC}"
    fi
else
    echo -e "${BLUE}[*] Auto-discovering r3ngine network...${NC}"
    # Find networks containing 'r3ngine'
    DISCOVERED_NETWORKS=$(docker network ls --format "{{.Name}}" | grep -i "r3ngine" || true)
    
    if [ -n "$DISCOVERED_NETWORKS" ]; then
        # Pick the first one
        TARGET_NETWORK=$(echo "$DISCOVERED_NETWORKS" | head -n 1)
        echo -e "${GREEN}[+] Discovered network: $TARGET_NETWORK${NC}"
    else
        # Fallback network name
        TARGET_NETWORK="r3ngine_network"
        echo -e "${YELLOW}[!] No matching r3ngine network discovered. Using fallback: $TARGET_NETWORK${NC}"
    fi
fi

# Find running containers matching container filter
echo -e "${BLUE}[*] Searching for running containers matching '$CONTAINER_FILTER'...${NC}"
# Use grep -i to make it case-insensitive
RUNNING_CONTAINERS=$(docker ps --filter "status=running" --format "{{.Names}}" | grep -i "$CONTAINER_FILTER" || true)

if [ -z "$RUNNING_CONTAINERS" ]; then
    echo -e "${YELLOW}[!] No running containers found matching '$CONTAINER_FILTER'.${NC}"
    echo -e "${BLUE}[*] Here are all currently running containers:${NC}"
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    exit 0
fi

# Loop through found containers and connect them if they aren't already
echo "$RUNNING_CONTAINERS" | while read -r CONTAINER; do
    [ -z "$CONTAINER" ] && continue
    echo -e "${BLUE}[*] Checking container: $CONTAINER${NC}"
    
    # Check if network exists. If dry-run, we might proceed but warning if not found
    if ! docker network inspect "$TARGET_NETWORK" &> /dev/null; then
        if [ "$DRY_RUN" = true ]; then
            echo -e "${YELLOW}[DRY-RUN] Target network '$TARGET_NETWORK' does not exist. Would attempt to connect anyway.${NC}"
        else
            echo -e "${RED}ERROR: Target network '$TARGET_NETWORK' does not exist. Cannot connect.$NC"
            continue
        fi
    fi

    # Check if already connected
    IS_CONNECTED=$(docker inspect "$CONTAINER" --format '{{json .NetworkSettings.Networks}}' | grep -i "\"$TARGET_NETWORK\"" || true)
    
    if [ -n "$IS_CONNECTED" ]; then
        echo -e "${GREEN}[+] Container '$CONTAINER' is already connected to network '$TARGET_NETWORK'.${NC}"
    else
        if [ "$DRY_RUN" = true ]; then
            echo -e "${YELLOW}[DRY-RUN] Would connect container '$CONTAINER' to network '$TARGET_NETWORK'.${NC}"
            echo -e "${YELLOW}[DRY-RUN] Command: docker network connect $TARGET_NETWORK $CONTAINER${NC}"
        else
            echo -e "${YELLOW}[*] Connecting '$CONTAINER' to '$TARGET_NETWORK'...${NC}"
            if docker network connect "$TARGET_NETWORK" "$CONTAINER"; then
                echo -e "${GREEN}[+] Successfully connected '$CONTAINER' to '$TARGET_NETWORK'.${NC}"
            else
                echo -e "${RED}ERROR: Failed to connect '$CONTAINER' to '$TARGET_NETWORK'.${NC}"
            fi
        fi
    fi
done

echo -e "\n${GREEN}[+] Done!${NC}"
