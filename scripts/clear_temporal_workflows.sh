#!/bin/bash

# ==================================================
# r3ngine – Clear Temporal Workflow Executions
# ==================================================
#
# Terminates all running Temporal workflows then deletes
# all closed workflow execution history from the server.
#
# Usage:
#   ./scripts/clear_temporal_workflows.sh [--namespace <ns>] [--dry-run] [--yes]
#
# Options:
#   --namespace <ns>   Temporal namespace to clean (default: "default")
#   --dry-run          List what would be cleared without making changes
#   --yes              Skip the confirmation prompt
# ==================================================

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Defaults ────────────────────────────────────────
NAMESPACE="default"
DRY_RUN=false
AUTO_YES=false
TEMPORAL_CONTAINER="r3ngine-temporal-1"

# ── Argument parsing ─────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --yes|-y)
            AUTO_YES=true
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Usage: $0 [--namespace <ns>] [--dry-run] [--yes]"
            exit 1
            ;;
    esac
done

# ── Banner ───────────────────────────────────────────
echo -e "${BLUE}"
echo "=================================================="
echo "      r3ngine – Clear Temporal Workflows"
echo "=================================================="
echo -e "${NC}"

# ── Sanity checks ────────────────────────────────────
if ! docker ps --format "{{.Names}}" | grep -q "^${TEMPORAL_CONTAINER}$"; then
    echo -e "${RED}ERROR: Container '${TEMPORAL_CONTAINER}' is not running.${NC}"
    echo "       Start the stack first: docker compose up -d"
    exit 1
fi

# Helper: run a temporal CLI command inside the container
temporal_exec() {
    docker exec "${TEMPORAL_CONTAINER}" temporal "$@" \
        --namespace "${NAMESPACE}" \
        --address "localhost:7233"
}

# ── Count workflows ───────────────────────────────────
echo -e "${CYAN}Namespace : ${NAMESPACE}${NC}"
echo -e "${CYAN}Container : ${TEMPORAL_CONTAINER}${NC}"
echo

echo "Counting workflow executions..."

RUNNING_COUNT=$(temporal_exec workflow list \
    --query "ExecutionStatus='Running'" \
    --output json --no-pager 2>/dev/null \
    | python3 -c "import sys,json; data=sys.stdin.read().strip(); print(len(json.loads(data)) if data and data!='null' else 0)" 2>/dev/null || echo "0")

ALL_COUNT=$(temporal_exec workflow list \
    --output json --no-pager 2>/dev/null \
    | python3 -c "import sys,json; data=sys.stdin.read().strip(); print(len(json.loads(data)) if data and data!='null' else 0)" 2>/dev/null || echo "0")

echo -e "  Running workflows  : ${YELLOW}${RUNNING_COUNT}${NC}"
echo -e "  Total (all states) : ${YELLOW}${ALL_COUNT}${NC}"
echo

if [[ "${DRY_RUN}" == "true" ]]; then
    echo -e "${YELLOW}[DRY RUN] No changes made. Re-run without --dry-run to proceed.${NC}"
    exit 0
fi

if [[ "${ALL_COUNT}" -eq 0 && "${RUNNING_COUNT}" -eq 0 ]]; then
    echo -e "${GREEN}Nothing to clear — namespace '${NAMESPACE}' is already empty.${NC}"
    exit 0
fi

# ── Confirmation ──────────────────────────────────────
if [[ "${AUTO_YES}" != "true" ]]; then
    echo -e "${YELLOW}WARNING: This will permanently terminate and delete all workflow"
    echo -e "         executions in namespace '${NAMESPACE}'.${NC}"
    echo
    read -r -p "Continue? [y/N] " REPLY
    if [[ ! "${REPLY}" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
    echo
fi

REASON="Manual cleanup via clear_temporal_workflows.sh"
EXIT_CODE=0

# ── Step 1: Terminate running workflows ───────────────
echo -e "${BLUE}[1/2] Terminating running workflow executions...${NC}"

if [[ "${RUNNING_COUNT}" -gt 0 ]]; then
    if temporal_exec workflow terminate \
        --query "ExecutionStatus='Running'" \
        --reason "${REASON}" \
        --yes 2>&1; then
        echo -e "${GREEN}      Done — ${RUNNING_COUNT} running workflow(s) terminated.${NC}"
    else
        echo -e "${YELLOW}      Warning: terminate step reported an error (may be partial).${NC}"
        EXIT_CODE=1
    fi
else
    echo "      No running workflows to terminate."
fi

echo

# ── Step 2: Delete all workflow executions ────────────
echo -e "${BLUE}[2/2] Deleting all workflow execution history...${NC}"

# Small pause so terminated workflows settle into a closed state
sleep 2

if temporal_exec workflow delete \
    --query "WorkflowType != ''" \
    --reason "${REASON}" \
    --yes 2>&1; then
    echo -e "${GREEN}      Done — all workflow execution history deleted.${NC}"
else
    echo -e "${YELLOW}      Warning: delete step reported an error (may be partial).${NC}"
    EXIT_CODE=1
fi

echo

# ── Summary ───────────────────────────────────────────
if [[ "${EXIT_CODE}" -eq 0 ]]; then
    echo -e "${GREEN}=================================================="
    echo -e "  Temporal namespace '${NAMESPACE}' cleared."
    echo -e "==================================================${NC}"
else
    echo -e "${YELLOW}=================================================="
    echo -e "  Completed with warnings. Some executions may"
    echo -e "  not have been cleared — check the Temporal UI:"
    echo -e "  http://localhost:8080"
    echo -e "==================================================${NC}"
fi

exit "${EXIT_CODE}"
