package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	watchdogStallKillMarker   = "WATCHDOG_STALL_KILL"
	watchdogTimeoutKillMarker = "WATCHDOG_TIMEOUT_KILL"
	hangDumpSnipBytes         = 16 * 1024
)

// progressTracker records whether a subprocess is making forward progress.
// Any non-stats line counts as progress. Nuclei -stats JSON only counts when
// requests or percent increase.
type progressTracker struct {
	mu           sync.Mutex
	lastProgress time.Time
	lastRequests int64
	lastPercent  float64
	haveStats    bool
}

func newProgressTracker(now time.Time) *progressTracker {
	return &progressTracker{lastProgress: now}
}

func (p *progressTracker) LastProgress() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastProgress
}

// ObserveLine updates progress from a stdout/stderr line. Returns true when
// the line advanced progress.
func (p *progressTracker) ObserveLine(line string, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}

	if advanced, ok := parseNucleiStatsProgress(trimmed, &p.lastRequests, &p.lastPercent, &p.haveStats); ok {
		if advanced {
			p.lastProgress = now
		}
		return advanced
	}

	p.lastProgress = now
	return true
}

// parseNucleiStatsProgress inspects a line for nuclei -stats JSON.
// ok=true means the line was stats JSON (progress only if requests/percent grew).
// ok=false means the line is not stats and should be treated as ordinary I/O.
func parseNucleiStatsProgress(line string, lastRequests *int64, lastPercent *float64, haveStats *bool) (advanced bool, ok bool) {
	if !strings.HasPrefix(line, "{") || !strings.Contains(line, `"percent"`) {
		return false, false
	}
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return false, false
	}
	// Findings have an "info" object; stats do not.
	if _, hasInfo := raw["info"]; hasInfo {
		return false, false
	}
	if _, hasPercent := raw["percent"]; !hasPercent {
		return false, false
	}

	requests := int64(parseStatsNumber(raw["requests"]))
	percent := parseStatsNumber(raw["percent"])

	if !*haveStats {
		*haveStats = true
		*lastRequests = requests
		*lastPercent = percent
		return true, true
	}
	if requests > *lastRequests || percent > *lastPercent {
		*lastRequests = requests
		*lastPercent = percent
		return true, true
	}
	return false, true
}

func parseStatsNumber(v interface{}) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case json.Number:
		f, _ := t.Float64()
		return f
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		if err != nil {
			return 0
		}
		return f
	case int:
		return float64(t)
	case int64:
		return float64(t)
	default:
		return 0
	}
}

// isHangMonitorDumpName reports whether name matches nuclei -hang-monitor dump files.
func isHangMonitorDumpName(name string) bool {
	base := filepath.Base(name)
	if strings.HasPrefix(base, "crash-resume-file-") && strings.HasSuffix(base, ".dump") {
		return true
	}
	if strings.Contains(base, "-stacktrace-") && strings.HasSuffix(base, ".dump") {
		return true
	}
	return false
}

// listNewHangMonitorDumps returns dump paths in dir created at or after since
// (mtime), excluding names already in seen.
func listNewHangMonitorDumps(dir string, since time.Time, seen map[string]struct{}) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var found []string
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if !isHangMonitorDumpName(name) {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		info, err := ent.Info()
		if err != nil {
			continue
		}
		// Allow a small clock skew window so dumps written at start are not missed.
		if info.ModTime().Before(since.Add(-2 * time.Second)) {
			continue
		}
		found = append(found, filepath.Join(dir, name))
	}
	return found
}

// snipFileHead returns up to maxBytes from the start of path.
func snipFileHead(path string, maxBytes int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, maxBytes)
	n, _ := f.Read(buf)
	if n <= 0 {
		return ""
	}
	return string(buf[:n])
}

// watchdogMarkers collects stderr markers appended by watchdogs.
type watchdogMarkers struct {
	mu   sync.Mutex
	buf  strings.Builder
	once map[string]struct{}
}

func newWatchdogMarkers() *watchdogMarkers {
	return &watchdogMarkers{once: make(map[string]struct{})}
}

func (m *watchdogMarkers) AppendOnce(marker string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.once[marker]; ok {
		return
	}
	m.once[marker] = struct{}{}
	m.buf.WriteString(marker)
	m.buf.WriteByte('\n')
}

func (m *watchdogMarkers) AppendText(text string) {
	if text == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.buf.WriteString(text)
	if !strings.HasSuffix(text, "\n") {
		m.buf.WriteByte('\n')
	}
}

func (m *watchdogMarkers) String() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.buf.String()
}
