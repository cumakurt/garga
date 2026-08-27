package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	barWidth           = 24
	drawInterval       = 100 * time.Millisecond
	minElapsedToShow   = 750 * time.Millisecond
	minSubmittedToShow = 8
	clearWidth         = 96
)

// Snapshot is a bounded-cardinality progress sample. It has no hosts or URLs.
type Snapshot struct {
	Submitted uint64
	Completed uint64
	Succeeded uint64
	Failed    uint64
}

// Options controls whether a writer is treated as an interactive terminal.
type Options struct {
	Force bool
}

// Bar redraws a single stderr line while a probe run is in progress.
type Bar struct {
	output  io.Writer
	enabled bool
	color   bool
	ascii   bool

	mu       sync.Mutex
	snapshot Snapshot
	started  time.Time
	shown    bool
	closed   bool
	lastDraw time.Time
}

// Open returns a bar that writes to output when it is a terminal, or when Force is set.
func Open(output io.Writer, options Options) *Bar {
	if output == nil {
		return &Bar{}
	}
	enabled := options.Force || isTerminal(output)
	return &Bar{
		output:  output,
		enabled: enabled,
		color:   enabled && colorEnabled(output),
		ascii:   os.Getenv("TERM") == "dumb",
		started: time.Now(),
	}
}

// Record stores the latest counters and redraws at a bounded rate.
func (bar *Bar) Record(snapshot Snapshot) {
	if bar == nil || !bar.enabled {
		return
	}
	bar.mu.Lock()
	defer bar.mu.Unlock()
	if bar.closed {
		return
	}
	if bar.started.IsZero() {
		bar.started = time.Now()
	}
	bar.snapshot = snapshot
	now := time.Now()
	if bar.shown && now.Sub(bar.lastDraw) < drawInterval {
		return
	}
	bar.drawLocked(now)
}

// Close erases the progress line. It is safe to call more than once.
func (bar *Bar) Close() error {
	if bar == nil || !bar.enabled {
		return nil
	}
	bar.mu.Lock()
	defer bar.mu.Unlock()
	if bar.closed {
		return nil
	}
	bar.closed = true
	if !bar.shown {
		return nil
	}
	_, err := io.WriteString(bar.output, "\r"+strings.Repeat(" ", clearWidth)+"\r")
	return err
}

func (bar *Bar) drawLocked(now time.Time) {
	elapsed := now.Sub(bar.started)
	if !bar.shown && !shouldShow(bar.snapshot, elapsed) {
		return
	}
	line := Format(bar.snapshot, elapsed, bar.color, bar.ascii)
	if line == "" {
		return
	}
	padding := ""
	if n := utf8.RuneCountInString(line); n < clearWidth {
		padding = strings.Repeat(" ", clearWidth-n)
	}
	if _, err := io.WriteString(bar.output, "\r"+line+padding); err != nil {
		return
	}
	bar.shown = true
	bar.lastDraw = now
}

// Enabled reports whether the bar will write to a terminal.
func (bar *Bar) Enabled() bool {
	return bar != nil && bar.enabled
}

func shouldShow(snapshot Snapshot, elapsed time.Duration) bool {
	if snapshot.Submitted == 0 && snapshot.Completed == 0 {
		return false
	}
	return snapshot.Submitted >= minSubmittedToShow || elapsed >= minElapsedToShow
}

// Format renders one progress line without a trailing newline.
func Format(snapshot Snapshot, elapsed time.Duration, color, ascii bool) string {
	total := snapshot.Submitted
	if snapshot.Completed > total {
		total = snapshot.Completed
	}
	percent := 0
	filled := 0
	if total > 0 {
		percent = int((snapshot.Completed * 100) / total)
		if percent > 100 {
			percent = 100
		}
		filled = int((snapshot.Completed * uint64(barWidth)) / total)
		if filled > barWidth {
			filled = barWidth
		}
	}

	fillChar := "█"
	emptyChar := "░"
	if ascii {
		fillChar = "#"
		emptyChar = "-"
	}
	meter := strings.Repeat(fillChar, filled) + strings.Repeat(emptyChar, barWidth-filled)
	if color {
		meter = paint(ansiCyan, meter)
	}

	parts := []string{
		meter,
		fmt.Sprintf("%d/%d", snapshot.Completed, total),
		fmt.Sprintf("%d%%", percent),
	}
	if snapshot.Succeeded > 0 || snapshot.Failed > 0 {
		parts = append(parts, fmt.Sprintf("ok %d", snapshot.Succeeded), fmt.Sprintf("fail %d", snapshot.Failed))
	}
	if elapsed > 0 && snapshot.Completed > 0 {
		rate := float64(snapshot.Completed) / elapsed.Seconds()
		parts = append(parts, fmt.Sprintf("%.0f/s", rate))
		remaining := total - snapshot.Completed
		if remaining > 0 && rate > 0 && snapshot.Completed >= 4 && elapsed >= time.Second {
			eta := time.Duration(float64(remaining)/rate) * time.Second
			parts = append(parts, "eta "+formatDuration(eta))
		}
	}
	return strings.Join(parts, "  ")
}

func formatDuration(value time.Duration) string {
	if value < time.Second {
		return "1s"
	}
	if value < time.Minute {
		return fmt.Sprintf("%ds", int(value.Round(time.Second).Seconds()))
	}
	minutes := int(value.Minutes())
	if minutes < 60 {
		seconds := int(value.Seconds()) % 60
		if seconds == 0 {
			return fmt.Sprintf("%dm", minutes)
		}
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	}
	hours := minutes / 60
	minutes %= 60
	if minutes == 0 {
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dh%dm", hours, minutes)
}

const (
	ansiReset = "\033[0m"
	ansiCyan  = "\033[36m"
)

func paint(code, text string) string {
	return code + text + ansiReset
}

func isTerminal(output io.Writer) bool {
	file, ok := output.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func colorEnabled(output io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return isTerminal(output)
}
