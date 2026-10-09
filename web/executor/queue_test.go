package main

import (
	"strings"
	"testing"
)

func TestExecutorTaskQueueMasterKeepsLegacyName(t *testing.T) {
	q, err := executorTaskQueue("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q != "go-executor-queue" {
		t.Fatalf("master queue = %q, want go-executor-queue", q)
	}
}

func TestExecutorTaskQueueWorkerGetsSuffix(t *testing.T) {
	cases := map[string]string{
		"w1":          "go-executor-queue-w1",
		"worker-eu-1": "go-executor-queue-worker-eu-1",
		"Node_2.prod": "go-executor-queue-Node_2.prod",
		"9":           "go-executor-queue-9",
	}
	for name, want := range cases {
		q, err := executorTaskQueue(name)
		if err != nil {
			t.Errorf("%q: unexpected error: %v", name, err)
			continue
		}
		if q != want {
			t.Errorf("%q: queue = %q, want %q", name, q, want)
		}
	}
}

func TestExecutorTaskQueueRejectsInvalidNames(t *testing.T) {
	invalid := []string{
		"-leading-dash",
		".leading-dot",
		"has space",
		"semi;colon",
		"slash/name",
		"tab\tname",
		"ünïcode",
		"a$b",
		strings.Repeat("x", 101),
	}
	for _, name := range invalid {
		q, err := executorTaskQueue(name)
		if err == nil {
			t.Errorf("%q: expected an error, got queue %q", name, q)
			continue
		}
		if !strings.Contains(err.Error(), "invalid worker name") {
			t.Errorf("%q: error %q does not name the problem", name, err)
		}
	}
}

func TestExecutorTaskQueueAcceptsMaximumLength(t *testing.T) {
	name := strings.Repeat("x", 100)
	if _, err := executorTaskQueue(name); err != nil {
		t.Fatalf("100-character name rejected: %v", err)
	}
}

func TestResolveWorkerNameFlagWinsOverEnv(t *testing.T) {
	cases := []struct {
		flag, env, want string
	}{
		{"", "", ""},
		{"", "from-env", "from-env"},
		{"from-flag", "", "from-flag"},
		{"from-flag", "from-env", "from-flag"},
	}
	for _, c := range cases {
		if got := resolveWorkerName(c.flag, c.env); got != c.want {
			t.Errorf("resolveWorkerName(%q, %q) = %q, want %q", c.flag, c.env, got, c.want)
		}
	}
}
