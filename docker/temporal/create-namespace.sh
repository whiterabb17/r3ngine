#!/bin/sh
# Run by the temporal-create-namespace service once the Temporal server is up.
# temporalio/auto-setup used to create the namespace itself; temporalio/server
# does not. The temporal healthcheck reads this namespace, so the workers wait
# for it.
set -eu

ADDRESS="${TEMPORAL_ADDRESS:-temporal:7233}"
NAMESPACE="${DEFAULT_NAMESPACE:-default}"
RETENTION="${DEFAULT_NAMESPACE_RETENTION:-24h}"

attempt=0
until temporal operator cluster health --address "$ADDRESS" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 90 ]; then
        echo "Temporal at $ADDRESS did not become healthy" >&2
        exit 1
    fi
    sleep 2
done

if temporal operator namespace describe -n "$NAMESPACE" --address "$ADDRESS" >/dev/null 2>&1; then
    echo "Namespace $NAMESPACE already exists"
else
    temporal operator namespace create -n "$NAMESPACE" --retention "$RETENTION" --address "$ADDRESS"
fi
