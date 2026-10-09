package main

import (
	"fmt"
	"regexp"
)

// defaultTaskQueue is the master's executor queue, polled when no worker name is set.
const defaultTaskQueue = "go-executor-queue"

// workerNameEnv is the variable docker-compose.worker.yml sets on both the
// Python orchestrator and this executor so the two agree on their queues.
const workerNameEnv = "WORKER_NAME"

// workerNamePattern is the charset Python accepts for a ScanWorker name
// (WORKER_NAME_PATTERN in web/reNgine/utils/task_queues.py). The name ends up
// in a Temporal queue name and a compose command line, hence the restriction.
var workerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// resolveWorkerName picks the worker name from the --worker-name flag and the
// WORKER_NAME environment variable; the flag wins when both are set. An empty
// result means this executor serves the master.
func resolveWorkerName(flagValue, envValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return envValue
}

// executorTaskQueue returns the Temporal task queue this executor polls:
// "go-executor-queue" for the master, "go-executor-queue-<name>" for a remote
// worker. It mirrors go_executor_queue() in web/reNgine/utils/task_queues.py,
// which is what the Python side on the same host routes tool runs to.
func executorTaskQueue(workerName string) (string, error) {
	if workerName == "" {
		return defaultTaskQueue, nil
	}
	if !workerNamePattern.MatchString(workerName) {
		return "", fmt.Errorf(
			"invalid worker name %q: use 1-100 characters from A-Z, a-z, 0-9, '.', '_' and '-', starting with a letter or digit",
			workerName,
		)
	}
	return defaultTaskQueue + "-" + workerName, nil
}
