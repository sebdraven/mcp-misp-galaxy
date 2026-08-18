// Command mcp-misp-galaxy loads the MISP galaxy corpus into an in-memory graph
// and serves it over MCP (stdio or streamable HTTP) or a REST API.
//
// Three deployment shapes, all supported:
//
//	repository   the corpus is a git submodule the process syncs to the
//	             pinned commit at start, and never moves past unless asked
//	standalone   a downloaded binary with no repository, pointed at a corpus
//	             directory with -data and populated by the fetch subcommand
//	container    the corpus is baked into the image, with no git at all
//
// A -resolve flag runs one lookup and exits, which is the cheapest way to check
// the graph before putting a transport in front of it.
package main

import (
	"context"
	"encoding/json"
	"errors"
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

// version is injected at build time with -ldflags "-X main.version=...".
// The default is deliberately "dev" rather than a number: a locally built
// binary that announces a release version lies to whoever reads it, and the
// MCP client shows this string as the server's identity.
var version = "dev"

func main() {
	// The fetch subcommand comes before flag parsing: it is a different
	// program with different arguments, and folding it into the server's flag
	// set would suggest the server itself might clone — which is exactly what
	// it must not do. An MCP client waits on the initialisation response, and
	// cloning 50,000 files under it looks like a hang.
	if len(os.Args) > 1 && os.Args[1] == "fetch" {
		log.SetOutput(os.Stderr)
		if err := runFetch(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}

	var (
		root          = flag.String("root", envOr("GALAXY_ROOT", "."), "parent repository holding the misp-galaxy submodule")
		submodule     = flag.String("submodule", envOr("GALAXY_SUBMODULE", corpus.SubmodulePath), "submodule path inside the repository")
		dataDir       = flag.String("data", envOr("GALAXY_DATA", ""), "corpus directory holding clusters/ and galaxies/; overrides the submodule, for a standalone binary")
		transport     = flag.String("transport", envOr("GALAXY_TRANSPORT", "stdio"), "transport: stdio, http (MCP over streamable HTTP) or rest")
		addr          = flag.String("addr", envOr("GALAXY_ADDR", ":8090"), "listen address for http and rest")
		noSync        = flag.Bool("no-sync", false, "skip the submodule sync and load whatever is already checked out")
		progress      = flag.Bool("progress", false, "force the load progress bar even when stderr is not a terminal")
		scope         = flag.String("scope", envOr("GALAXY_SCOPE", ""), "comma-separated galaxies to search by default; empty uses the built-in CTI scope, \"all\" searches the whole corpus")
		resolveQ      = flag.String("resolve", "", "resolve one name, print the ranked candidates as JSON, and exit")
		normalisation = flag.String("normalisation", envOr("GALAXY_NORMALISATION", "standard"), "name folding for -resolve: standard or aggressive")
		showGx        = flag.Bool("galaxies", false, "print the galaxy inventory with entry counts and exit")
		showStats     = flag.Bool("stats", false, "print load statistics and exit")
		showVer       = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	// Before anything touches the corpus: asking the version should never need
	// a checkout, a network, or half a second of graph building.
	if *showVer {
		fmt.Println(version)
		return
	}

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

	// An explicit -data means the corpus lives outside any repository, so the
	// submodule machinery is bypassed entirely rather than half-applied.
	data := strings.TrimSpace(*dataDir)
	if data != "" {
		if data, err = filepath.Abs(data); err != nil {
			log.Fatalf("resolving -data: %v", err)
		}
		if !corpus.Usable(data) {
			log.Fatalf("no corpus at %s\nhint: mcp-misp-galaxy fetch -data %s", data, data)
		}
	}

	if data == "" && !*noSync && mgr.Available() {
		start := time.Now()
		// Only warn when there is actually something to clone: on an existing
		// checkout the sync is a no-op and the message is just noise.
		if st, err := mgr.Status(); err == nil && !st.Ready {
			fmt.Fprintln(os.Stderr, "corpus not checked out yet: cloning the full misp-galaxy history, this takes a while")
		}
		st, err := mgr.Sync()
		switch {
		case errors.Is(err, corpus.ErrSyncFailed):
			// A usable corpus is on disk, just not the pinned one. Refusing to
			// start here would trade a slightly stale answer for no answer at
			// all — and the commit actually loaded is reported everywhere, so
			// nothing is passed off as current that is not.
			log.Printf("warning: %v", err)
			log.Printf("serving the corpus already on disk (commit %s); run `git submodule update --init %s` to fix",
				short(st.Current), *submodule)
		case err != nil:
			log.Fatalf("submodule sync failed: %v\n"+
				"hint: run `git submodule update --init %s` once, then retry with -no-sync", err, *submodule)
		default:
			log.Printf("corpus synced in %s (commit %s)", time.Since(start).Round(time.Millisecond), short(st.Current))
		}
	} else if data == "" && !mgr.Available() {
		// A baked-in corpus, as in a container image. Normal, but say so:
		// nothing here can move the data, and provenance comes from
		// GALAXY_CORPUS_REF rather than from git.
		log.Print("no git repository at root: using the corpus as it sits on disk")
	}

	holder := &galaxy.Holder{}
	var svcOpts []service.Option
	if s := strings.TrimSpace(*scope); s != "" {
		svcOpts = append(svcOpts, service.WithScope(strings.Split(s, ",")))
	}
	if data != "" {
		svcOpts = append(svcOpts, service.WithDataDir(data))
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
		res, err := svc.Resolve(*resolveQ, nil, 0, true, *normalisation)
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

// runFetch clones or updates a standalone corpus checkout.
//
// Separate from the server on purpose, the same way Sync and Advance are kept
// apart: whatever changes the data is always an explicit act, never a side
// effect of starting something.
func runFetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	dir := fs.String("data", envOr("GALAXY_DATA", corpus.DefaultDataDir()), "where to put the corpus")
	url := fs.String("url", corpus.UpstreamURL, "corpus repository to clone")
	ref := fs.String("ref", "", "commit to check out; empty follows the default branch")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: mcp-misp-galaxy fetch [flags]\n\n"+
			"Clone or update the MISP galaxy corpus, then serve it with:\n"+
			"  mcp-misp-galaxy -data <dir>\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	dest, err := filepath.Abs(*dir)
	if err != nil {
		return fmt.Errorf("resolving -data: %w", err)
	}

	start := time.Now()
	fmt.Fprintf(os.Stderr, "corpus destination: %s\n", dest)
	sha, err := corpus.Fetch(context.Background(), dest, *url, *ref, os.Stderr)
	if err != nil {
		return err
	}
	if !corpus.Usable(dest) {
		return fmt.Errorf("fetched %s but found no clusters/ under %s", short(sha), dest)
	}
	fmt.Fprintf(os.Stderr, "ready: %d cluster files at commit %s (%s)\n",
		corpus.CountClusters(dest), short(sha), time.Since(start).Round(time.Millisecond))
	fmt.Fprintf(os.Stderr, "serve it with: mcp-misp-galaxy -data %s\n", dest)
	// stdout carries the path alone, so it can be captured:
	//   mcp-misp-galaxy -data "$(mcp-misp-galaxy fetch)"
	fmt.Println(dest)
	return nil
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
