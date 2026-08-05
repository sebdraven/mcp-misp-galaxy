// Package ui renders load progress on a terminal.
//
// It degrades to silence whenever stderr is not a character device — piped
// output, a log file, a CI job. Carriage returns and escape codes in a log are
// worse than no progress at all, and this is the only place that decides.
package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// barWidth is the drawn width of the gauge itself, excluding label and counter.
const barWidth = 32

// minRedraw throttles redraws. The corpus holds thousands of files and
// repainting on every one costs more than the parsing does.
const minRedraw = 60 * time.Millisecond

// Progress renders phased progress. The zero value is unusable; build one with
// NewProgress.
type Progress struct {
	mu       sync.Mutex
	w        io.Writer
	enabled  bool
	phase    string
	lastDraw time.Time
	started  time.Time
	width    int // characters written on the current line, for erasing
}

// NewProgress returns a Progress writing to stderr, active only when stderr is
// a terminal. force overrides the detection, which is what -progress is for.
func NewProgress(force bool) *Progress {
	return &Progress{
		w:       os.Stderr,
		enabled: force || isTerminal(os.Stderr),
		started: time.Now(),
	}
}

// Disabled reports whether rendering is off, so callers can skip building
// progress data at all.
func (p *Progress) Disabled() bool { return p == nil || !p.enabled }

// Update is the callback handed to the loader: a phase name, how far along it
// is, and its total. total <= 0 means the phase has no known size, in which
// case only the count is shown.
func (p *Progress) Update(phase string, done, total int) {
	if p.Disabled() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	newPhase := phase != p.phase
	if newPhase {
		// Finish the previous line before starting a new one.
		if p.phase != "" {
			p.erase()
		}
		p.phase = phase
	}
	// Always draw the first and last frame of a phase; throttle the rest.
	final := total > 0 && done >= total
	if !newPhase && !final && time.Since(p.lastDraw) < minRedraw {
		return
	}
	p.lastDraw = time.Now()
	p.draw(phase, done, total)
}

// Done clears the progress line and prints a closing summary.
func (p *Progress) Done(summary string) {
	if p.Disabled() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.erase()
	p.phase = ""
	if summary != "" {
		fmt.Fprintf(p.w, "%s (%s)\n", summary, time.Since(p.started).Round(time.Millisecond))
	}
}

func (p *Progress) draw(phase string, done, total int) {
	var line string
	if total > 0 {
		if done > total {
			done = total
		}
		filled := done * barWidth / total
		line = fmt.Sprintf("%-10s [%s%s] %d/%d",
			phase,
			strings.Repeat("=", filled),
			strings.Repeat(" ", barWidth-filled),
			done, total)
	} else {
		line = fmt.Sprintf("%-10s %d", phase, done)
	}
	// Pad over whatever the previous, possibly longer, line left behind.
	pad := 0
	if p.width > len(line) {
		pad = p.width - len(line)
	}
	fmt.Fprintf(p.w, "\r%s%s", line, strings.Repeat(" ", pad))
	p.width = len(line)
}

func (p *Progress) erase() {
	if p.width == 0 {
		return
	}
	fmt.Fprintf(p.w, "\r%s\r", strings.Repeat(" ", p.width))
	p.width = 0
}

// isTerminal reports whether f is a character device. Deliberately done with
// os.Stat rather than a dependency: it is accurate enough here and keeps the
// binary free of a terminal library for one boolean.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
