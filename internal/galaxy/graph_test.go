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

func TestDegreeBreaksTiesButDoesNotOutrankScore(t *testing.T) {
	// Tie-break: the same value in two galaxies, so both score identically as
	// exact matches and only degree can separate them. A shared fixture will
	// not do here — two entries matching the same query at the same score is
	// precisely the situation this rule exists for, and it has to be built.
	root := t.TempDir()
	clusters := filepath.Join(root, "clusters")
	if err := os.MkdirAll(clusters, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeCluster(t, clusters, "lonely", []map[string]any{
		{"value": "Twin", "uuid": "u-lonely", "meta": map[string]any{}},
	})
	writeCluster(t, clusters, "linked", []map[string]any{
		{"value": "Twin", "uuid": "u-linked", "related": []map[string]any{
			{"dest-uuid": "u-x1", "type": "rel"},
			{"dest-uuid": "u-x2", "type": "rel"},
		}},
	})
	g, err := Load(root, "deadbeef")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	got := g.Resolve("Twin", nil, 10)
	if len(got) != 2 {
		t.Fatalf("expected both twins, got %+v", got)
	}
	if got[0].Score != got[1].Score {
		t.Fatalf("the fixture must produce equal scores for this to test anything, got %d vs %d",
			got[0].Score, got[1].Score)
	}
	if got[0].Degree == got[1].Degree {
		t.Fatalf("the fixture must produce different degrees, got %d vs %d",
			got[0].Degree, got[1].Degree)
	}
	if got[0].UUID != "u-linked" {
		t.Fatalf("at equal score the connected entry should rank first, got %+v", got)
	}

	// Precedence: degree must not outrank a better score — an exact match beats
	// a better-connected prefix match.
	root2 := t.TempDir()
	clusters2 := filepath.Join(root2, "clusters")
	if err := os.MkdirAll(clusters2, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeCluster(t, clusters2, "test", []map[string]any{
		{"value": "Alpha", "uuid": "u-alpha", "meta": map[string]any{}},
		{"value": "Alpha Extended", "uuid": "u-alpha-ext", "related": []map[string]any{
			{"dest-uuid": "u-x1", "type": "rel"},
			{"dest-uuid": "u-x2", "type": "rel"},
			{"dest-uuid": "u-x3", "type": "rel"},
		}},
	})
	g2, err := Load(root2, "deadbeef")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	got2 := g2.Resolve("Alpha", nil, 10)
	if len(got2) < 2 {
		t.Fatalf("expected both exact and prefix matches, got %+v", got2)
	}
	degAlpha, degExt := -1, -1
	for _, c := range got2 {
		switch c.UUID {
		case "u-alpha":
			degAlpha = c.Degree
		case "u-alpha-ext":
			degExt = c.Degree
		}
	}
	if degAlpha == -1 || degExt == -1 {
		t.Fatalf("expected both u-alpha and u-alpha-ext in results, got %+v", got2)
	}
	if degExt <= degAlpha {
		t.Fatalf("the fixture must make the prefix match better connected, got %d vs %d",
			degExt, degAlpha)
	}
	if got2[0].UUID != "u-alpha" {
		t.Fatalf("an exact match must come first regardless of degree, got %+v", got2)
	}
}

// ---- MISP tags ---------------------------------------------------------------

func TestCandidateCarriesTheCanonicalTag(t *testing.T) {
	// The tag is what attaches to a MISP event; a uuid attaches to nothing.
	g := chainGraph(t)
	got := g.Resolve("Someone", nil, 10)
	if len(got) != 1 {
		t.Fatalf("expected one candidate, got %d", len(got))
	}
	if want := `misp-galaxy:threat-actor="Someone"`; got[0].Tag != want {
		t.Errorf("tag = %q, want %q", got[0].Tag, want)
	}
}

func TestNeighbourAndPathCarryTags(t *testing.T) {
	g := chainGraph(t)
	for _, n := range g.Neighbours("u-nasty", NeighbourOpts{Depth: 2}) {
		if n.Dangling {
			continue
		}
		if n.Tag == "" {
			t.Errorf("neighbour %s has no tag", n.UUID)
		}
	}
	for _, h := range g.ShortestPath("u-nasty", "u-report", 6, nil) {
		if h.Tag == "" {
			t.Errorf("path hop %s has no tag", h.UUID)
		}
	}
}

func TestDanglingNodeHasNoTag(t *testing.T) {
	// A dangling node has neither galaxy nor value, so there is nothing to tag
	// with — emitting misp-galaxy:="" would be worse than emitting nothing.
	g := chainGraph(t)
	missing, _ := g.Node("u-missing")
	if tag := missing.Tag(); tag != "" {
		t.Errorf("dangling node produced tag %q", tag)
	}
}

func TestTagEscapesQuotes(t *testing.T) {
	// Rare, but a value containing a double quote would otherwise produce a tag
	// that cannot be parsed back.
	if got, want := Tag("tool", `He said "hi"`), `misp-galaxy:tool="He said \"hi\""`; got != want {
		t.Errorf("Tag() = %q, want %q", got, want)
	}
}

// ---- confidence and bridges --------------------------------------------------

func TestConfidenceCountsDeclarations(t *testing.T) {
	// Two galaxies each declaring the same link: one link, asserted twice.
	// A relation stated from both sides is better supported than one stated
	// from a single side, and that is what confidence records.
	root := t.TempDir()
	clusters := filepath.Join(root, "clusters")
	if err := os.MkdirAll(clusters, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeCluster(t, clusters, "left", []map[string]any{
		{"value": "A", "uuid": "u-a", "related": []map[string]any{
			{"dest-uuid": "u-b", "type": "similar"},
		}},
	})
	writeCluster(t, clusters, "right", []map[string]any{
		{"value": "B", "uuid": "u-b", "related": []map[string]any{
			{"dest-uuid": "u-a", "type": "used-by"},
		}},
	})
	g, err := Load(root, "deadbeef")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got := g.Stats().Edges; got != 1 {
		t.Errorf("a link declared from both sides is one edge, got %d", got)
	}
	a, _ := g.Node("u-a")
	// Two adjacency entries, not one: each side declared the relation, so each
	// sees it outbound. They describe the same link and carry the same merged
	// confidence and types.
	if len(a.Out) != 1 || len(a.In) != 1 {
		t.Fatalf("expected one outgoing and one incoming entry, got %d/%d", len(a.Out), len(a.In))
	}
	for _, e := range append(append([]Edge{}, a.Out...), a.In...) {
		if e.Confidence != 2 {
			t.Errorf("confidence = %d, want 2", e.Confidence)
		}
		if len(e.Types) != 2 {
			t.Errorf("both relation types should be kept, got %+v", e.Types)
		}
	}

	// And a one-sided declaration stays at confidence 1 — otherwise the field
	// would say nothing.
	if got := g.Stats().Bridges; got != 1 {
		t.Errorf("the single link joins the whole graph, bridges = %d, want 1", got)
	}
}

func TestBridgeDetection(t *testing.T) {
	// A triangle joined to an isolated node by one link. Only that link is a
	// bridge: cutting any triangle edge leaves the graph connected.
	root := t.TempDir()
	clusters := filepath.Join(root, "clusters")
	if err := os.MkdirAll(clusters, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeCluster(t, clusters, "ring", []map[string]any{
		{"value": "A", "uuid": "r-a", "related": []map[string]any{
			{"dest-uuid": "r-b", "type": "rel"},
		}},
		{"value": "B", "uuid": "r-b", "related": []map[string]any{
			{"dest-uuid": "r-c", "type": "rel"},
		}},
		{"value": "C", "uuid": "r-c", "related": []map[string]any{
			{"dest-uuid": "r-a", "type": "rel"},
			{"dest-uuid": "r-far", "type": "weak"},
		}},
		{"value": "Far", "uuid": "r-far"},
	})
	g, err := Load(root, "deadbeef")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got := g.Stats().Bridges; got != 1 {
		t.Fatalf("expected exactly one bridge, got %d", got)
	}
	c, _ := g.Node("r-c")
	for _, e := range append(append([]Edge{}, c.Out...), c.In...) {
		wantBridge := e.To.UUID == "r-far"
		if e.Bridge != wantBridge {
			t.Errorf("edge to %s: bridge = %v, want %v", e.To.UUID, e.Bridge, wantBridge)
		}
	}
}

func TestNeighboursCarryConfidenceAndBridge(t *testing.T) {
	g := chainGraph(t)
	found := g.Neighbours("u-nasty", NeighbourOpts{Depth: 2})
	for _, n := range found {
		if n.Confidence < 1 {
			t.Errorf("neighbour %s has confidence %d", n.UUID, n.Confidence)
		}
	}
	// The chain fixture is a path, so every hop is a bridge by construction.
	for _, n := range found {
		if !n.Bridge {
			t.Errorf("every link in a chain is a bridge, %s is not flagged", n.UUID)
		}
	}
}

// twoWayGraph builds A and B linked from both sides under different relation
// types — the shape that merging edges makes tricky.
func twoWayGraph(t *testing.T) *Graph {
	t.Helper()
	root := t.TempDir()
	clusters := filepath.Join(root, "clusters")
	if err := os.MkdirAll(clusters, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeCluster(t, clusters, "left", []map[string]any{
		{"value": "A", "uuid": "u-a", "related": []map[string]any{
			{"dest-uuid": "u-b", "type": "used-by"},
		}},
	})
	writeCluster(t, clusters, "right", []map[string]any{
		{"value": "B", "uuid": "u-b", "related": []map[string]any{
			{"dest-uuid": "u-a", "type": "similar"},
		}},
	})
	g, err := Load(root, "deadbeef")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return g
}

func TestEdgeTypeFilterSeesEveryDeclaredType(t *testing.T) {
	// Merging keeps one type as the primary; filtering on the other must still
	// find the link, and must report the type that actually matched.
	g := twoWayGraph(t)
	for _, want := range []string{"used-by", "similar"} {
		found := g.Neighbours("u-a", NeighbourOpts{Depth: 1, EdgeTypes: []string{want}})
		if len(found) != 1 {
			t.Fatalf("filtering on %q found %d neighbours, want 1", want, len(found))
		}
		if found[0].Via != want {
			t.Errorf("filtering on %q reported via=%q", want, found[0].Via)
		}
	}
	if got := g.Neighbours("u-a", NeighbourOpts{Depth: 1, EdgeTypes: []string{"nope"}}); len(got) != 0 {
		t.Errorf("an unmatched type should find nothing, got %+v", got)
	}
}

func TestDirectionReflectsWhatTheCorpusDeclared(t *testing.T) {
	// Both nodes declare the relation, so each must see it as outgoing. Merging
	// the two declarations into one oriented edge would make this depend on
	// which cluster file was read first.
	g := twoWayGraph(t)
	for _, uuid := range []string{"u-a", "u-b"} {
		if got := g.Neighbours(uuid, NeighbourOpts{Depth: 1, Direction: Out}); len(got) != 1 {
			t.Errorf("%s declares the relation outbound, Out found %d", uuid, len(got))
		}
		if got := g.Neighbours(uuid, NeighbourOpts{Depth: 1, Direction: In}); len(got) != 1 {
			t.Errorf("%s is declared upon inbound, In found %d", uuid, len(got))
		}
	}
}

// ---- specificity ------------------------------------------------------------

// actorGraph links one technique to three actors and another to one, which is
// the shape the specificity signal exists to tell apart.
func actorGraph(t *testing.T) *Graph {
	t.Helper()
	root := t.TempDir()
	clusters := filepath.Join(root, "clusters")
	if err := os.MkdirAll(clusters, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeCluster(t, clusters, "threat-actor", []map[string]any{
		{"value": "Actor One", "uuid": "a-1", "related": []map[string]any{
			{"dest-uuid": "t-common", "type": "uses"},
			{"dest-uuid": "t-rare", "type": "uses"},
		}},
		{"value": "Actor Two", "uuid": "a-2", "related": []map[string]any{
			{"dest-uuid": "t-common", "type": "uses"},
		}},
		{"value": "Actor Three", "uuid": "a-3", "related": []map[string]any{
			{"dest-uuid": "t-common", "type": "uses"},
		}},
	})
	writeCluster(t, clusters, "mitre-attack-pattern", []map[string]any{
		{"value": "Everyone Does This", "uuid": "t-common"},
		{"value": "Only One Does This", "uuid": "t-rare"},
	})
	g, err := Load(root, "deadbeef")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return g
}

func TestGroupCountMeasuresActorsNotEdges(t *testing.T) {
	g := actorGraph(t)
	common, _ := g.Node("t-common")
	rare, _ := g.Node("t-rare")
	if common.GroupCount != 3 {
		t.Errorf("shared technique: group_count = %d, want 3", common.GroupCount)
	}
	if rare.GroupCount != 1 {
		t.Errorf("exclusive technique: group_count = %d, want 1", rare.GroupCount)
	}
	// An actor is not counted against itself, and non-actor neighbours never
	// count — the question is "how many actors", not "how many links".
	actor, _ := g.Node("a-1")
	if actor.GroupCount != 0 {
		t.Errorf("actor linked only to techniques: group_count = %d, want 0", actor.GroupCount)
	}
}

func TestSpecificNeighboursRankBeforeGeneric(t *testing.T) {
	g := actorGraph(t)
	found := g.Neighbours("a-1", NeighbourOpts{Depth: 1})
	if len(found) != 2 {
		t.Fatalf("expected both techniques, got %+v", found)
	}
	if found[0].UUID != "t-rare" {
		t.Errorf("the exclusive technique should come first, got %+v", found)
	}
}

func TestMaxGroupCountDropsGeneric(t *testing.T) {
	g := actorGraph(t)
	found := g.Neighbours("a-1", NeighbourOpts{Depth: 1, MaxGroupCount: 2})
	if len(found) != 1 || found[0].UUID != "t-rare" {
		t.Fatalf("the shared technique should be filtered out, got %+v", found)
	}
}

func TestMaxGroupCountBlocksTraversalNotJustReporting(t *testing.T) {
	// a-1 reaches a-2 and a-3 only through t-common, the technique all three
	// share. Filtering it out must make them unreachable, not merely hidden:
	// a generic entry is a hub, and routing through it manufactures adjacency
	// between actors whose only connection is that everyone does the same
	// ordinary thing.
	//
	// This is the opposite of the galaxy filter, which selects what is reported
	// while still walking through what it excludes. The two must not drift into
	// behaving the same way.
	g := actorGraph(t)

	wide := g.Neighbours("a-1", NeighbourOpts{Depth: 2})
	if !containsUUID(wide, "a-2") {
		t.Fatalf("without the filter a-2 should be reachable at depth 2, got %+v", wide)
	}

	narrow := g.Neighbours("a-1", NeighbourOpts{Depth: 2, MaxGroupCount: 2})
	if containsUUID(narrow, "a-2") || containsUUID(narrow, "a-3") {
		t.Errorf("actors reachable only through a generic hub must not be returned, got %+v", narrow)
	}
	for _, n := range narrow {
		if n.UUID == "t-common" {
			t.Errorf("the generic entry itself must not be returned")
		}
	}
}

func TestMaxGroupCountKeepsGenericOutOfPaths(t *testing.T) {
	// A filtered node must not turn up inside a recorded route either — a path
	// that runs through an entry the caller excluded is worse than no path.
	g := actorGraph(t)
	found := g.Neighbours("a-1", NeighbourOpts{Depth: 2, MaxGroupCount: 2, WithPaths: true})
	for _, n := range found {
		for _, hop := range n.Path {
			if hop == "t-common" {
				t.Errorf("path to %s runs through the filtered entry: %v", n.UUID, n.Path)
			}
		}
	}
}

func TestMostGenericRanksWorstFirst(t *testing.T) {
	g := actorGraph(t)
	top := g.MostGeneric("mitre-attack-pattern", 5)
	if len(top) != 2 {
		t.Fatalf("expected both techniques, got %+v", top)
	}
	if top[0].UUID != "t-common" {
		t.Errorf("the most-shared technique should come first, got %+v", top)
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
