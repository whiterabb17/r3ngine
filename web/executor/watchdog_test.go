package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProgressTrackerNonStatsLineAdvances(t *testing.T) {
	now := time.Unix(1000, 0)
	p := newProgressTracker(now)
	later := now.Add(30 * time.Second)
	if !p.ObserveLine("[INF] Templates loaded", later) {
		t.Fatal("expected non-stats line to advance progress")
	}
	if !p.LastProgress().Equal(later) {
		t.Fatalf("lastProgress = %v, want %v", p.LastProgress(), later)
	}
}

func TestProgressTrackerStatsWithoutDeltaDoesNotAdvance(t *testing.T) {
	now := time.Unix(2000, 0)
	p := newProgressTracker(now)
	stats := `{"duration":"1m","errors":"0","hosts":"10","matched":"0","percent":"5","requests":"100","rps":"10","templates":"50"}`
	if !p.ObserveLine(stats, now.Add(time.Second)) {
		t.Fatal("first stats line should advance progress")
	}
	stuckAt := p.LastProgress()
	same := `{"duration":"2m","errors":"0","hosts":"10","matched":"0","percent":"5","requests":"100","rps":"0","templates":"50"}`
	if p.ObserveLine(same, now.Add(2*time.Minute)) {
		t.Fatal("unchanged stats must not advance progress")
	}
	if !p.LastProgress().Equal(stuckAt) {
		t.Fatalf("lastProgress moved on unchanged stats: %v -> %v", stuckAt, p.LastProgress())
	}
}

func TestProgressTrackerStatsDeltaAdvances(t *testing.T) {
	now := time.Unix(3000, 0)
	p := newProgressTracker(now)
	first := `{"percent":"10","requests":"50"}`
	if !p.ObserveLine(first, now.Add(time.Second)) {
		t.Fatal("first stats should advance")
	}
	next := `{"percent":"11","requests":"60"}`
	later := now.Add(time.Minute)
	if !p.ObserveLine(next, later) {
		t.Fatal("increased requests/percent should advance")
	}
	if !p.LastProgress().Equal(later) {
		t.Fatalf("lastProgress = %v, want %v", p.LastProgress(), later)
	}
}

func TestProgressTrackerFindingJSONIsNotStats(t *testing.T) {
	now := time.Unix(4000, 0)
	p := newProgressTracker(now)
	finding := `{"template-id":"x","info":{"name":"n","severity":"info"},"percent":"0"}`
	later := now.Add(5 * time.Second)
	if !p.ObserveLine(finding, later) {
		t.Fatal("finding lines should count as ordinary progress")
	}
	// A later unchanged-looking stats object should still register as first stats.
	stats := `{"percent":"0","requests":"0"}`
	if !p.ObserveLine(stats, later.Add(time.Second)) {
		t.Fatal("first real stats after a finding should advance")
	}
}

func TestIsHangMonitorDumpName(t *testing.T) {
	cases := map[string]bool{
		"nuclei-stacktrace-123.dump":     true,
		"foo-stacktrace-bar.dump":        true,
		"crash-resume-file-1.dump":       true,
		"crash-resume-file-abc.dump":     true,
		"notes.dump":                     false,
		"stacktrace.dump":                false,
		"crash-resume-file.txt":          false,
		"nuclei-stacktrace-123.log":      false,
	}
	for name, want := range cases {
		if got := isHangMonitorDumpName(name); got != want {
			t.Errorf("isHangMonitorDumpName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestListNewHangMonitorDumps(t *testing.T) {
	dir := t.TempDir()
	since := time.Now().Add(-time.Minute)
	dump := filepath.Join(dir, "nuclei-stacktrace-test.dump")
	if err := os.WriteFile(dump, []byte("goroutine 1 [semacquire]:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "other.txt"), []byte("x"), 0o644)

	found := listNewHangMonitorDumps(dir, since, map[string]struct{}{})
	if len(found) != 1 || filepath.Base(found[0]) != "nuclei-stacktrace-test.dump" {
		t.Fatalf("found = %v, want nuclei-stacktrace-test.dump", found)
	}

	seen := map[string]struct{}{"nuclei-stacktrace-test.dump": {}}
	if again := listNewHangMonitorDumps(dir, since, seen); len(again) != 0 {
		t.Fatalf("expected seen dumps skipped, got %v", again)
	}
}

func TestSnipFileHead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.dump")
	body := strings.Repeat("A", 100) + strings.Repeat("B", 100)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	snip := snipFileHead(path, 50)
	if len(snip) != 50 {
		t.Fatalf("snip len = %d, want 50", len(snip))
	}
	if snip != strings.Repeat("A", 50) {
		t.Fatalf("unexpected snip content %q", snip)
	}
}

func TestWatchdogMarkersAppendOnce(t *testing.T) {
	m := newWatchdogMarkers()
	m.AppendOnce(watchdogStallKillMarker)
	m.AppendOnce(watchdogStallKillMarker)
	m.AppendOnce(watchdogTimeoutKillMarker)
	out := m.String()
	if strings.Count(out, watchdogStallKillMarker) != 1 {
		t.Fatalf("stall marker count wrong in %q", out)
	}
	if strings.Count(out, watchdogTimeoutKillMarker) != 1 {
		t.Fatalf("timeout marker count wrong in %q", out)
	}
}
