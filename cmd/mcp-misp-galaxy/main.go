// Command mcp-misp-galaxy loads the MISP galaxy corpus into an in-memory graph
// and serves it over MCP (stdio or streamable HTTP) or a REST API.
//
// The corpus is a git submodule the process manages itself: at start it brings
// the checkout to the commit the repository pins, and never moves past it
// unless asked. A -resolve flag runs one lookup and exits, which is the
// cheapest way to check the graph before putting a transport in front of it.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sebdraven/mcp-misp-galaxy/internal/corpus"
	"github.com/sebdraven/mcp-misp-galaxy/internal/galaxy"
	"github.com/sebdraven/mcp-misp-galaxy/internal/httpapi"
	"github.com/sebdraven/mcp-misp-galaxy/internal/mcptools"
	"github.com/sebdraven/mcp-misp-galaxy/internal/service"
	"github.com/sebdraven/mcp-misp-galaxy/internal/ui"
)

var version = "0.1.0"

func main() {
	var (
		root      = flag.String("root", envOr("GALAXY_ROOT", "."), "parent repository holding the misp-galaxy submodule")
		submodule = flag.String("submodule", envOr("GALAXY_SUBMODULE", corpus.SubmodulePath), "submodule path inside the repository")
		transport = flag.String("transport", envOr("GALAXY_TRANSPORT", "stdio"), "transport: stdio, http (MCP over streamable HTTP) or rest")
		addr      = flag.String("addr", envOr("GALAXY_ADDR", ":8090"), "listen address for http and rest")
		noSync    = flag.Bool("no-sync", false, "skip the submodule sync and load whatever is already checked out")
		progress  = flag.Bool("progress", false, "force the load progress bar even when stderr is not a terminal")
		scope     = flag.String("scope", envOr("GALAXY_SCOPE", ""), "comma-separated galaxies to search by default; empty uses the built-in CTI scope, \"all\" searches the whole corpus")
		resolveQ  = flag.String("resolve", "", "resolve one name, print the ranked candidates as JSON, and exit")
		showGx    = flag.Bool("galaxies", false, "print the galaxy inventory with entry counts and exit")
		showStats = flag.Bool("stats", false, "print load statistics and exit")
	)
	flag.Parse()

	// stdio carries the protocol, so every log goes to stderr regardless of
	// transport — a stray line on stdout corrupts the stream.
	log.SetOutput(os.Stderr)

	absRoot, err := filepath.Abs(*root)
	if err != nil {
		log.Fatalf("resolving root: %v", err)
	}
	mgr, err := corpus.NewManager(absRoot, *submodule)
	if err != nil {
		log.Fatalf("corpus: %v", err)
	}

	if !*noSync {
		start := time.Now()
		// Only warn when there is actually something to clone: on an existing
		// checkout the sync is a no-op and the message is just noise.
		if st, err := mgr.Status(); err == nil && !st.Ready {
			fmt.Fprintln(os.Stderr, "corpus not checked out yet: cloning the full misp-galaxy history, this takes a while")
		}
		st, err := mgr.Sync()
		if err != nil {
			log.Fatalf("submodule sync failed: %v\n"+
				"hint: run `git submodule update --init %s` once, then retry with -no-sync", err, *submodule)
		}
		log.Printf("corpus synced in %s (commit %s)", time.Since(start).Round(time.Millisecond), short(st.Current))
	}

	holder := &galaxy.Holder{}
	var svcOpts []service.Option
	if s := strings.TrimSpace(*scope); s != "" {
		svcOpts = append(svcOpts, service.WithScope(strings.Split(s, ",")))
	}
	svc := service.New(holder, mgr, svcOpts...)

	start := time.Now()
	bar := ui.NewProgress(*progress)
	stats, err := svc.Reload(galaxy.WithProgress(bar.Update))
	if err != nil {
		bar.Done("")
		log.Fatalf("loading corpus: %v", err)
	}
	bar.Done("graph built")
	log.Printf("graph built in %s from corpus %s: %d nodes, %d edges, %d galaxies, %d dangling, %d revoked",
		time.Since(start).Round(time.Millisecond), short(stats.SourceRef),
		stats.Nodes, stats.Edges, stats.Galaxies, stats.Dangling, stats.Revoked)

	// A galaxy named in the scope but absent from the checkout is almost always
	// a typo, and it fails silently as "no results" — so say so once at start.
	if g := holder.Get(); g != nil {
		for _, want := range svc.Scope() {
			if !g.HasGalaxy(want) {
				log.Printf("warning: scope names galaxy %q, absent or empty in this checkout", want)
			}
		}
	}

	// One-shot modes: useful before wiring any transport.
	if *showStats {
		printJSON(svc.Status())
		return
	}
	if *showGx {
		gs, err := svc.Galaxies()
		if err != nil {
			log.Fatal(err)
		}
		// Sorted by size rather than by name: the question this answers is
		// "which galaxies actually carry weight", and 131 alphabetical lines
		// do not answer it.
		sort.Slice(gs, func(i, j int) bool { return gs[i].Nodes > gs[j].Nodes })
		for _, g := range gs {
			fmt.Printf("%7d  %-42s %s\n", g.Nodes, g.Type, g.Name)
		}
		return
	}
	if *resolveQ != "" {
		res, err := svc.Resolve(*resolveQ, nil, 0, true)
		if err != nil {
			log.Fatal(err)
		}
		printJSON(res)
		return
	}

	switch *transport {
	case "rest":
		log.Printf("mcp-misp-galaxy %s REST on %s", version, *addr)
		if err := http.ListenAndServe(*addr, httpapi.Handler(svc)); err != nil {
			log.Fatal(err)
		}
	case "stdio", "http":
		server := mcp.NewServer(&mcp.Implementation{
			Name:    "mcp-misp-galaxy",
			Version: version,
		}, nil)
		mcptools.Register(server, svc)

		if *transport == "stdio" {
			log.Printf("mcp-misp-galaxy %s on stdio", version)
			if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
				log.Fatal(err)
			}
			return
		}
		handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
		log.Printf("mcp-misp-galaxy %s MCP on %s (streamable HTTP)", version, *addr)
		if err := http.ListenAndServe(*addr, handler); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unknown transport %q (want stdio, http or rest)", *transport)
	}
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func short(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
