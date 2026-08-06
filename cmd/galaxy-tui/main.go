// Command galaxy-tui explores the MISP galaxy graph interactively.
//
// A separate binary from mcp-misp-galaxy on purpose: the terminal UI pulls in
// bubbletea, bubbles and lipgloss, and none of that belongs in a container
// image whose job is to answer MCP calls.
//
// Strictly read-only. There is no key binding that moves the corpus checkout:
// bumping the data is a decision that belongs in a commit, not in a keystroke
// pressed while exploring.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/sebdraven/mcp-misp-galaxy/internal/corpus"
	"github.com/sebdraven/mcp-misp-galaxy/internal/galaxy"
	"github.com/sebdraven/mcp-misp-galaxy/internal/service"
	"github.com/sebdraven/mcp-misp-galaxy/internal/ui"
)

func main() {
	var (
		root      = flag.String("root", envOr("GALAXY_ROOT", "."), "parent repository holding the misp-galaxy submodule")
		submodule = flag.String("submodule", envOr("GALAXY_SUBMODULE", corpus.SubmodulePath), "submodule path inside the repository")
		scope     = flag.String("scope", envOr("GALAXY_SCOPE", ""), "comma-separated galaxies to search; empty uses the built-in CTI scope, \"all\" searches the whole corpus")
		noSync    = flag.Bool("no-sync", false, "skip the submodule sync and load whatever is already checked out")
		markFmt   = flag.String("marks", "text", "how to print marked entries on exit: text or json")
	)
	flag.Parse()

	// The UI owns stdout once it starts; keep the loading chatter on stderr so
	// piping the marked trail to a file stays clean.
	log.SetOutput(os.Stderr)

	absRoot, err := filepath.Abs(*root)
	if err != nil {
		log.Fatalf("resolving root: %v", err)
	}
	mgr, err := corpus.NewManager(absRoot, *submodule)
	if err != nil {
		log.Fatalf("corpus: %v", err)
	}
	if !*noSync && mgr.Available() {
		if st, err := mgr.Status(); err == nil && !st.Ready {
			fmt.Fprintln(os.Stderr, "corpus not checked out yet: cloning the full misp-galaxy history, this takes a while")
		}
		if _, err := mgr.Sync(); err != nil {
			log.Fatalf("submodule sync failed: %v", err)
		}
	}

	var opts []service.Option
	if s := strings.TrimSpace(*scope); s != "" {
		opts = append(opts, service.WithScope(strings.Split(s, ",")))
	}
	holder := &galaxy.Holder{}
	svc := service.New(holder, mgr, opts...)

	start := time.Now()
	bar := ui.NewProgress(false)
	stats, err := svc.Reload(galaxy.WithProgress(bar.Update))
	if err != nil {
		bar.Done("")
		log.Fatalf("loading corpus: %v", err)
	}
	bar.Done(fmt.Sprintf("loaded %d entries, %d relations in %s",
		stats.Nodes, stats.Edges, time.Since(start).Round(time.Millisecond)))

	p := tea.NewProgram(newModel(svc), tea.WithAltScreen())
	final, err := p.Run()
	if err != nil {
		log.Fatal(err)
	}

	// The whole point of marking: the trail survives the session.
	if m, ok := final.(model); ok && len(m.marks) > 0 {
		printMarks(m.marks, *markFmt, stats.SourceRef)
	}
}

func printMarks(marks []mark, format, sourceRef string) {
	// The corpus commit travels with the trail. A list of UUIDs with no corpus
	// state behind it cannot be replayed six months later, and that is exactly
	// when someone will want to.
	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		_ = enc.Encode(map[string]any{
			"corpus_commit": sourceRef,
			"count":         len(marks),
			"marks":         marks,
		})
		return
	}
	fmt.Printf("# misp-galaxy corpus %s\n", sourceRef)
	for _, m := range marks {
		fmt.Printf("%s\t%s\t%s\n", m.UUID, m.Galaxy, m.Value)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
