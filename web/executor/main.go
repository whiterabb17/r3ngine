package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
)

type ToolExecutionInput struct {
	Command    []string `json:"command"`
	ScanID     int      `json:"scan_id"`
	CommandID  int      `json:"command_id"`
	WorkingDir string   `json:"working_dir"`
}

type ToolExecutionResult struct {
	Stdout     string  `json:"stdout"`
	Stderr     string  `json:"stderr"`
	ExitCode   int     `json:"exit_code"`
	TimeTakenS float64 `json:"time_taken_s"`
}

type RedisLogPayload struct {
	Line      string `json:"line"`
	Timestamp string `json:"timestamp"`
	CommandID int    `json:"command_id"`
}

type Activities struct {
	rdb *redis.Client
}

// SubprocessActivity executes the tool and sends heartbeats back to Temporal, while streaming logs to Redis
func (a *Activities) SubprocessActivity(ctx context.Context, input ToolExecutionInput) (ToolExecutionResult, error) {
	activity.GetLogger(ctx).Info("Starting subprocess tool execution", "command", input.Command)

	if len(input.Command) == 0 {
		return ToolExecutionResult{ExitCode: 1}, fmt.Errorf("empty command")
	}

	var cmd *exec.Cmd
	if len(input.Command) == 1 {
		cmd = exec.CommandContext(ctx, "/bin/bash", "-c", input.Command[0])
	} else {
		cmd = exec.CommandContext(ctx, input.Command[0], input.Command[1:]...)
	}
	if input.WorkingDir != "" {
		cmd.Dir = input.WorkingDir
	}
	// Place the subprocess in its own process group so all children (nuclei, amass, etc.)
	// receive SIGKILL when the Temporal context is cancelled, not just the bash shell.
	// setCmdProcessGroup is defined in pgid_linux.go (Linux) / pgid_other.go (other OS).
	setCmdProcessGroup(cmd)

	var stdoutBuf, stderrBuf bytes.Buffer
	pr, pw := io.Pipe()

	// MultiWriter to write to both the buffer, the Redis stream pipe, and os.Stdout/os.Stderr
	cmd.Stdout = io.MultiWriter(&stdoutBuf, pw, os.Stdout)
	cmd.Stderr = io.MultiWriter(&stderrBuf, pw, os.Stderr)

	fmt.Printf("[GO-EXECUTOR] Running (scan_id=%d): %s\n", input.ScanID, strings.Join(input.Command, " "))

	start := time.Now()
	if err := cmd.Start(); err != nil {
		pw.Close()
		return ToolExecutionResult{
			Stderr:   err.Error(),
			ExitCode: -1,
		}, err
	}

	killProcessGroup := func(reason string) {
		if cmd.Process == nil {
			return
		}
		activity.GetLogger(ctx).Warn("Force-killing subprocess group", "reason", reason, "pid", cmd.Process.Pid, "scan_id", input.ScanID)
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}

	// Keep heartbeating to Temporal every 5 seconds to prevent activity timeout
	stopHeartbeat := make(chan bool)
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				activity.RecordHeartbeat(ctx, fmt.Sprintf("running: %v elapsed", time.Since(start)))
			case <-stopHeartbeat:
				return
			}
		}
	}()
	defer close(stopHeartbeat)

	// Independent stop watchdog: if the scan stop kill switch is set in Redis,
	// kill the entire process group even if Temporal cancellation did not reach
	// this executor activity cleanly.
	stopKillWatch := make(chan bool)
	if a.rdb != nil && input.ScanID > 0 {
		go func() {
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					killKey := fmt.Sprintf("scan_stop_%d", input.ScanID)
					val, err := a.rdb.Get(context.Background(), killKey).Result()
					if err == nil && val == "1" {
						killProcessGroup("scan stop kill switch")
						return
					}
				case <-stopKillWatch:
					return
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	defer close(stopKillWatch)

	// Goroutine to read from pipe line-by-line and send to Redis stream
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer pr.Close()
		scanner := bufio.NewScanner(pr)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024) // 1MB maximum line buffer
		for scanner.Scan() {
			line := scanner.Text()
			if a.rdb != nil && input.ScanID > 0 {
				streamKey := fmt.Sprintf("scan:logs:%d", input.ScanID)
				payload := RedisLogPayload{
					Line:      line,
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					CommandID: input.CommandID,
				}
				jsonBytes, err := json.Marshal(payload)
				if err == nil {
					err = a.rdb.XAdd(ctx, &redis.XAddArgs{
						Stream: streamKey,
						MaxLen: 1000,
						Approx: true,
						Values: map[string]interface{}{
							"data": string(jsonBytes),
						},
					}).Err()
					if err != nil {
						activity.GetLogger(ctx).Warn("Failed to publish log to Redis", "error", err)
					}
				}
			}
		}
		if err := scanner.Err(); err != nil {
			activity.GetLogger(ctx).Error("Scanner error in executor", "error", err)
		}
	}()

	// Wait for tool completion
	err := cmd.Wait()
	pw.Close() // Trigger EOF for scanner
	wg.Wait()  // Ensure all logs are read and streamed
	timeTaken := time.Since(start).Seconds()

	var exitCode int
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			ws := exitError.Sys().(syscall.WaitStatus)
			exitCode = ws.ExitStatus()
		} else {
			exitCode = -2
		}
	}

	return ToolExecutionResult{
		Stdout:     stdoutBuf.String(),
		Stderr:     stderrBuf.String(),
		ExitCode:   exitCode,
		TimeTakenS: timeTaken,
	}, nil
}

func main() {
	workerNameFlag := flag.String("worker-name", "", "remote worker name; polls go-executor-queue-<name> instead of go-executor-queue (overrides WORKER_NAME)")
	flag.Parse()

	// Resolve the queue before anything else so a misconfigured worker exits
	// with a clear message instead of silently serving the master's queue.
	workerName := resolveWorkerName(*workerNameFlag, os.Getenv(workerNameEnv))
	taskQueue, err := executorTaskQueue(workerName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "r3ngine-executor: %v\n", err)
		os.Exit(2)
	}
	if workerName == "" {
		fmt.Printf("[GO-EXECUTOR] No worker name (master): serving task queue %s\n", taskQueue)
	} else {
		fmt.Printf("[GO-EXECUTOR] Worker %q: serving task queue %s\n", workerName, taskQueue)
	}

	temporalHost := os.Getenv("TEMPORAL_HOST")
	if temporalHost == "" {
		temporalHost = "temporal:7233"
	}
	namespace := os.Getenv("TEMPORAL_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}

	// Connect to Redis
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "redis://redis:6379/0"
	}
	var rdb *redis.Client
	opt, err := redis.ParseURL(redisURL)
	if err == nil {
		rdb = redis.NewClient(opt)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := rdb.Ping(ctx).Err(); err != nil {
			fmt.Printf("Warning: Failed to ping Redis at %s: %v\n", redisURL, err)
		} else {
			fmt.Printf("Connected to Redis at %s\n", redisURL)
		}
	} else {
		fmt.Printf("Warning: Failed to parse Redis URL %s: %v\n", redisURL, err)
	}

	var c client.Client
	maxRetries := 30
	retryInterval := 2 * time.Second

	for i := 1; i <= maxRetries; i++ {
		c, err = client.Dial(client.Options{
			HostPort:  temporalHost,
			Namespace: namespace,
		})
		if err == nil {
			break
		}
		fmt.Printf("Failed to connect to Temporal (attempt %d/%d): %v. Retrying in %v...\n", i, maxRetries, err, retryInterval)
		time.Sleep(retryInterval)
	}
	if err != nil {
		panic(fmt.Sprintf("failed reaching server: %v", err))
	}
	defer c.Close()

	w := worker.New(c, taskQueue, worker.Options{})

	activities := &Activities{rdb: rdb}

	// Register subprocess command worker activity
	w.RegisterActivityWithOptions(activities.SubprocessActivity, activity.RegisterOptions{
		Name: "RunToolSubprocessActivity",
	})

	err = w.Run(worker.InterruptCh())
	if err != nil {
		panic(err)
	}
}
