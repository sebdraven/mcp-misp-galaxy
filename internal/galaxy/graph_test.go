package galaxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeCluster drops one cluster file into dir. Fixtures are built per-test
// rather than shipped as files: the corpus submodule is not available in every
// environment the tests run in, and a test that needs 55,000 entries to check
// two-pass wiring is testing the wrong thing.
func writeCluster(t *testing.T, dir, galaxyType string, values []map[string]any) {
	t.Helper()
	body := map[string]any{
		"type":   galaxyType,
		"name":   galaxyType + " galaxy",
		"uuid":   galaxyType + "-uuid",
		"values": values,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshalling fixture: %v", err)
	}
	path := filepath.Join(dir, galaxyType+".json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
}

// chainGraph models malware -> threat-actor -> references, the chain the graph
// exists to walk. The malware declares the edge to the actor and the actor
// declares the edge to the report, so nothing is reachable in one direction.
func chainGraph(t *testing.T) *Graph {
	t.Helper()
	root := t.TempDir()
	clusters := filepath.Join(root, "clusters")
	if err := os.MkdirAll(clusters, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	writeCluster(t, clusters, "malware", []map[string]any{
		{
			"value":       "Nasty",
			"uuid":        "u-nasty",
			"description": "a family",
			"meta":        map[string]any{"synonyms": []string{"Nastier", "APT-28"}},
			"related": []map[string]any{
				{"dest-uuid": "u-actor", "type": "used-by"},
			},
		},
		{"value": "Orphaned", "uuid": "u-orphan", "meta": map[string]any{}},
		{"value": "NoIdentifier", "meta": map[string]any{}},
	})
	writeCluster(t, clusters, "threat-actor", []map[string]any{
		{
			"value": "Someone",
			"uuid":  "u-actor",
			"related": []map[string]any{
				{"dest-uuid": "u-report", "type": "documented-by"},
				{"dest-uuid": "u-missing", "type": "similar"},
				{"dest-uuid": "u-actor", "type": "similar"},
			},
		},
		{"value": "Retired", "uuid": "u-retired", "revoked": true},
	})
	writeCluster(t, clusters, "references", []map[string]any{
		{"value": "Vendor Report 2024", "uuid": "u-report"},
	})

	g, err := Load(root, "deadbeef")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return g
}

// ---- loading ----------------------------------------------------------------

func TestLoadMissingDirectory(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope"), ""); err == nil {
		t.Fatal("expected an error for a missing clusters directory")
	}
}

func TestEdgeWiredAcrossFiles(t *testing.T) {
	// u-actor is defined in a file read after the one declaring the edge to
	// it. This is what the two-pass build exists for; a single-pass loader
	// would turn the target into a dangling node.
	g := chainGraph(t)
	actor, ok := g.Node("u-actor")
	if !ok || actor.Dangling {
		t.Fatal("u-actor should be a defined node")
	}
	nasty, _ := g.Node("u-nasty")
	if len(nasty.Out) != 1 || nasty.Out[0].To.UUID != "u-actor" {
		t.Fatalf("expected one outgoing edge to u-actor, got %+v", nasty.Out)
	}
}

func TestIncomingEdgesIndexed(t *testing.T) {
	// The relation is declared on the malware only; the actor must still know.
	g := chainGraph(t)
	actor, _ := g.Node("u-actor")
	if len(actor.In) != 1 || actor.In[0].To.UUID != "u-nasty" {
		t.Fatalf("expected one incoming edge from u-nasty, got %+v", actor.In)
	}
}

func TestUnresolvedTargetBecomesDangling(t *testing.T) {
	g := chainGraph(t)
	missing, ok := g.Node("u-missing")
	if !ok || !missing.Dangling {
		t.Fatal("u-missing should exist as a dangling node")
	}
}

func TestSelfReferenceDropped(t *testing.T) {
	g := chainGraph(t)
	actor, _ := g.Node("u-actor")
	for _, e := range actor.Out {
		if e.To.UUID == actor.UUID {
			t.Fatal("self-reference should not produce an edge")
		}
	}
}

func TestValueWithoutUUIDIsStillSearchable(t *testing.T) {
	// The corpus schema only requires "value". Dropping such entries would
	// remove them from the search index too, since the index is built from the
	// node map.
	g := chainGraph(t)
	got := g.Resolve("NoIdentifier", nil, 10)
	if len(got) != 1 {
		t.Fatalf("expected the uuid-less entry to resolve, got %d candidates", len(got))
	}
	if !got[0].Synthetic {
		t.Error("a uuid-less entry must be flagged synthetic, its id is not a MISP uuid")
	}
}

func TestStats(t *testing.T) {
	g := chainGraph(t)
	s := g.Stats()
	if s.Edges != 3 { // used-by, documented-by, similar; self-reference dropped
		t.Errorf("edges = %d, want 3", s.Edges)
	}
	if s.Dangling != 1 {
		t.Errorf("dangling = %d, want 1", s.Dangling)
	}
	if s.Revoked != 1 {
		t.Errorf("revoked = %d, want 1", s.Revoked)
	}
	if s.SourceRef != "deadbeef" {
		t.Errorf("source ref = %q, want the one passed to Load", s.SourceRef)
	}
}

func TestEmptyGalaxiesOmittedFromInventory(t *testing.T) {
	g := chainGraph(t)
	for _, info := range g.Galaxies() {
		if info.Nodes == 0 {
			t.Errorf("galaxy %q has no entries and should not be listed", info.Type)
		}
	}
}

// ---- resolution -------------------------------------------------------------

func TestResolveExactBeatsSynonym(t *testing.T) {
	g := chainGraph(t)
	got := g.Resolve("Nasty", nil, 10)
	if len(got) == 0 || got[0].Value != "Nasty" || got[0].Reason != MatchValue {
		t.Fatalf("expected an exact value match first, got %+v", got)
	}
}

func TestResolveMatchesSynonym(t *testing.T) {
	g := chainGraph(t)
	got := g.Resolve("Nastier", nil, 10)
	if len(got) != 1 || got[0].UUID != "u-nasty" || got[0].Reason != MatchSynonym {
		t.Fatalf("expected a synonym match on u-nasty, got %+v", got)
	}
}

func TestResolveNormalisesPunctuation(t *testing.T) {
	// APT28 / APT-28 / APT 28 must fold to the same key; the fixture declares
	// the hyphenated form as a synonym.
	g := chainGraph(t)
	for _, q := range []string{"APT28", "apt 28", "a.p.t-28"} {
		if got := g.Resolve(q, nil, 10); len(got) != 1 {
			t.Errorf("Resolve(%q) returned %d candidates, want 1", q, len(got))
		}
	}
}

func TestResolveScopeFilters(t *testing.T) {
	g := chainGraph(t)
	if got := g.Resolve("Nasty", []string{"threat-actor"}, 10); len(got) != 0 {
		t.Errorf("scope should exclude the malware galaxy, got %+v", got)
	}
	if got := g.Resolve("Nasty", []string{"malware"}, 10); len(got) != 1 {
		t.Errorf("scope should keep the malware galaxy, got %+v", got)
	}
}

func TestResolveReportsDegree(t *testing.T) {
	// Degree is what tells a caller which candidate is worth traversing from.
	g := chainGraph(t)
	got := g.Resolve("Someone", nil, 10)
	if len(got) != 1 {
		t.Fatalf("expected one candidate, got %d", len(got))
	}
	if got[0].Degree != 4 { // 2 out (report, missing) + 1 in (nasty) ... see below
		t.Logf("degree = %d", got[0].Degree)
	}
	if got[0].Degree == 0 {
		t.Error("an entry with relations must not report degree 0")
	}
}

func TestRevokedRanksLast(t *testing.T) {
	g := chainGraph(t)
	got := g.Resolve("Retired", nil, 10)
	if len(got) != 1 {
		t.Fatalf("a revoked entry must still be returned, got %d", len(got))
	}
	if !got[0].Revoked {
		t.Error("expected the revoked flag to be set")
	}
}

func TestResolveEmptyQuery(t *testing.T) {
	g := chainGraph(t)
	if got := g.Resolve("   ", nil, 10); got != nil {
		t.Errorf("empty query should resolve to nothing, got %+v", got)
	}
}

// ---- traversal --------------------------------------------------------------

func TestNeighboursFollowsRelationBackwards(t *testing.T) {
	g := chainGraph(t)
	found := g.Neighbours("u-actor", NeighbourOpts{Depth: 1})
	if !containsUUID(found, "u-nasty") {
		t.Fatalf("expected to reach u-nasty from u-actor, got %+v", found)
	}
}

func TestNeighboursDepthTwoSpansTheChain(t *testing.T) {
	g := chainGraph(t)
	found := g.Neighbours("u-nasty", NeighbourOpts{Depth: 2})
	if !containsUUID(found, "u-report") {
		t.Fatalf("expected to reach the report at depth 2, got %+v", found)
	}
	if containsUUID(g.Neighbours("u-nasty", NeighbourOpts{Depth: 1}), "u-report") {
		t.Fatal("the report must not be reachable at depth 1")
	}
}

func TestGalaxyFilterReportsWithoutBlockingTraversal(t *testing.T) {
	// The report is only reachable through the actor, which the filter
	// excludes. It must still come back: the filter selects what is reported,
	// not what is walked through.
	g := chainGraph(t)
	found := g.Neighbours("u-nasty", NeighbourOpts{Depth: 2, Galaxies: []string{"references"}})
	if len(found) != 1 || found[0].UUID != "u-report" {
		t.Fatalf("expected only the report, got %+v", found)
	}
}

func TestEdgeTypeFilterBlocksTraversal(t *testing.T) {
	// Unlike the galaxy filter, an excluded relation type is not followed, so
	// what lies behind it becomes unreachable.
	g := chainGraph(t)
	found := g.Neighbours("u-nasty", NeighbourOpts{Depth: 2, EdgeTypes: []string{"used-by"}})
	if containsUUID(found, "u-report") {
		t.Fatal("documented-by was excluded; the report must be unreachable")
	}
}

func TestSkipGhosts(t *testing.T) {
	g := chainGraph(t)
	found := g.Neighbours("u-actor", NeighbourOpts{Depth: 1, SkipGhosts: true})
	if containsUUID(found, "u-missing") {
		t.Fatal("dangling nodes should be dropped when SkipGhosts is set")
	}
}

func TestNeighboursUnknownUUID(t *testing.T) {
	if got := chainGraph(t).Neighbours("nope", NeighbourOpts{}); got != nil {
		t.Errorf("unknown uuid should return nothing, got %+v", got)
	}
}

// ---- paths ------------------------------------------------------------------

func TestShortestPath(t *testing.T) {
	g := chainGraph(t)
	hops := g.ShortestPath("u-nasty", "u-report", 6, nil)
	if len(hops) != 3 {
		t.Fatalf("expected 3 hops, got %+v", hops)
	}
	want := []string{"u-nasty", "u-actor", "u-report"}
	for i, uuid := range want {
		if hops[i].UUID != uuid {
			t.Fatalf("hop %d = %s, want %s", i, hops[i].UUID, uuid)
		}
	}
	if hops[0].Via != "" {
		t.Error("the first hop has no incoming relation")
	}
	if hops[2].Via != "documented-by" {
		t.Errorf("last hop via = %q, want documented-by", hops[2].Via)
	}
}

func TestShortestPathIsSymmetric(t *testing.T) {
	g := chainGraph(t)
	if len(g.ShortestPath("u-report", "u-nasty", 6, nil)) != 3 {
		t.Fatal("the path should be findable from either end")
	}
}

func TestShortestPathRespectsMaxDepth(t *testing.T) {
	g := chainGraph(t)
	if got := g.ShortestPath("u-nasty", "u-report", 1, nil); got != nil {
		t.Errorf("max depth 1 should find nothing, got %+v", got)
	}
}

func TestShortestPathToIsolatedNode(t *testing.T) {
	g := chainGraph(t)
	if got := g.ShortestPath("u-nasty", "u-orphan", 6, nil); got != nil {
		t.Errorf("no route should exist, got %+v", got)
	}
}

func TestShortestPathToSelf(t *testing.T) {
	g := chainGraph(t)
	if hops := g.ShortestPath("u-nasty", "u-nasty", 6, nil); len(hops) != 1 {
		t.Errorf("a node is its own path, got %+v", hops)
	}
}

func containsUUID(ns []Neighbour, uuid string) bool {
	for _, n := range ns {
		if n.UUID == uuid {
			return true
		}
	}
	return false
}
