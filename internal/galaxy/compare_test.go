package galaxy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// compareGraph gives two actors a shared exclusive technique, a shared generic
// one, and one technique each of their own — enough to tell a meaningful
// overlap from a meaningless one.
func compareGraph(t *testing.T) *Graph {
	t.Helper()
	root := t.TempDir()
	clusters := filepath.Join(root, "clusters")
	if err := os.MkdirAll(clusters, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	actors := []map[string]any{
		{"value": "Actor A", "uuid": "a-1", "related": []map[string]any{
			{"dest-uuid": "t-both", "type": "uses"},
			{"dest-uuid": "t-common", "type": "uses"},
			{"dest-uuid": "t-a-only", "type": "uses"},
		}},
		{"value": "Actor B", "uuid": "b-1", "related": []map[string]any{
			{"dest-uuid": "t-both", "type": "uses"},
			{"dest-uuid": "t-common", "type": "uses"},
			{"dest-uuid": "t-b-only", "type": "uses"},
		}},
	}
	// Ten more actors, all using the common technique and nothing else, so it
	// clears the generic threshold while t-both stays exclusive to the pair.
	for i := 0; i < 10; i++ {
		actors = append(actors, map[string]any{
			"value": fmt.Sprintf("Bystander %d", i), "uuid": fmt.Sprintf("c-%d", i),
			"related": []map[string]any{{"dest-uuid": "t-common", "type": "uses"}},
		})
	}
	writeCluster(t, clusters, "threat-actor", actors)
	writeCluster(t, clusters, "mitre-attack-pattern", []map[string]any{
		{"value": "Shared And Rare", "uuid": "t-both"},
		{"value": "Everyone Does This", "uuid": "t-common"},
		{"value": "Only A", "uuid": "t-a-only"},
		{"value": "Only B", "uuid": "t-b-only"},
	})

	g, err := Load(root, "deadbeef")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return g
}

func TestCompareExcludesGenericFromScore(t *testing.T) {
	// The literature's warning made concrete: leaving in what every actor
	// shares makes every pair look alike. Here the generic technique would
	// otherwise account for half the overlap.
	g := compareGraph(t)

	common, _ := g.Node("t-common")
	both, _ := g.Node("t-both")
	if common.GroupCount != 12 || both.GroupCount != 2 {
		t.Fatalf("fixture broken: common=%d both=%d, want 12 and 2",
			common.GroupCount, both.GroupCount)
	}

	cmp, ok := g.Compare("a-1", "b-1", CompareOpts{})
	if !ok {
		t.Fatal("expected a comparison")
	}
	for _, e := range cmp.Shared {
		if e.UUID == "t-common" {
			t.Error("the generic technique should be excluded from the shared set")
		}
	}
	if cmp.GenericExcluded == 0 {
		t.Error("the count of excluded generic entries should say what was dropped")
	}
	// One shared, one unique each: 1/3.
	if want := 1.0 / 3.0; cmp.Similarity != want {
		t.Errorf("similarity = %v, want %v", cmp.Similarity, want)
	}
}

func TestCompareIncludeGenericInflatesSimilarity(t *testing.T) {
	// Offered as an option, but the effect is exactly what the default guards
	// against, and the two runs should differ.
	g := compareGraph(t)
	strict, _ := g.Compare("a-1", "b-1", CompareOpts{})
	loose, _ := g.Compare("a-1", "b-1", CompareOpts{IncludeGeneric: true})
	if loose.Similarity <= strict.Similarity {
		t.Errorf("including generic entries should raise similarity, got %v vs %v",
			loose.Similarity, strict.Similarity)
	}
}

func TestCompareSeparatesUniqueEntries(t *testing.T) {
	g := compareGraph(t)
	cmp, _ := g.Compare("a-1", "b-1", CompareOpts{})

	if cmp.SharedCount != 1 || cmp.Shared[0].UUID != "t-both" {
		t.Errorf("expected the rare technique as the only shared one, got %+v", cmp.Shared)
	}
	if cmp.AOnlyCount != 1 || cmp.AOnly[0].UUID != "t-a-only" {
		t.Errorf("expected one entry unique to A, got %+v", cmp.AOnly)
	}
	if cmp.BOnlyCount != 1 || cmp.BOnly[0].UUID != "t-b-only" {
		t.Errorf("expected one entry unique to B, got %+v", cmp.BOnly)
	}
}

func TestCompareNotesWhenOverlapIsAllGeneric(t *testing.T) {
	// Two actors sharing only what everybody uses are not related, and the
	// answer has to say so rather than report a score and leave it there.
	root := t.TempDir()
	clusters := filepath.Join(root, "clusters")
	if err := os.MkdirAll(clusters, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	actors := []map[string]any{
		{"value": "Actor A", "uuid": "a-1", "related": []map[string]any{
			{"dest-uuid": "t-common", "type": "uses"},
		}},
		{"value": "Actor B", "uuid": "b-1", "related": []map[string]any{
			{"dest-uuid": "t-common", "type": "uses"},
		}},
	}
	for i := 0; i < 10; i++ {
		actors = append(actors, map[string]any{
			"value": fmt.Sprintf("Bystander %d", i), "uuid": fmt.Sprintf("c-%d", i),
			"related": []map[string]any{{"dest-uuid": "t-common", "type": "uses"}},
		})
	}
	writeCluster(t, clusters, "threat-actor", actors)
	writeCluster(t, clusters, "mitre-attack-pattern", []map[string]any{
		{"value": "Everyone Does This", "uuid": "t-common"},
	})
	g, err := Load(root, "deadbeef")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	cmp, _ := g.Compare("a-1", "b-1", CompareOpts{IncludeGeneric: true})
	if cmp.Note == "" {
		t.Error("an overlap made only of widely-used entries should be called out")
	}
}

func TestCompareRanksDiscriminatingEntriesFirst(t *testing.T) {
	// An entry linked to two actors says more about a pair than one linked to
	// fifty, so it has to lead the shared list.
	g := compareGraph(t)
	cmp, _ := g.Compare("a-1", "b-1", CompareOpts{IncludeGeneric: true})
	if len(cmp.Shared) < 2 {
		t.Fatalf("expected both shared entries, got %+v", cmp.Shared)
	}
	if cmp.Shared[0].UUID != "t-both" {
		t.Errorf("the rare shared entry should lead, got %+v", cmp.Shared)
	}
}

func TestCompareDoesNotRelateThroughGenericHubs(t *testing.T) {
	// Hiding a generic entry from the results is not enough: if the walk still
	// passes through it, two actors share everything on its far side and the
	// filter achieves nothing at depth > 1. This is the same reasoning as
	// MaxGroupCount on neighbours — a widely-used entry is a hub, and routing
	// through it manufactures adjacency.
	root := t.TempDir()
	clusters := filepath.Join(root, "clusters")
	if err := os.MkdirAll(clusters, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Two actors whose only link is a technique everybody uses. Behind that
	// technique sits a third actor and its own tooling.
	actors := []map[string]any{
		{"value": "Actor A", "uuid": "a-1", "related": []map[string]any{
			{"dest-uuid": "t-hub", "type": "uses"},
		}},
		{"value": "Actor B", "uuid": "b-1", "related": []map[string]any{
			{"dest-uuid": "t-hub", "type": "uses"},
		}},
	}
	for i := 0; i < 12; i++ {
		actors = append(actors, map[string]any{
			"value": fmt.Sprintf("Bystander %d", i), "uuid": fmt.Sprintf("c-%d", i),
			"related": []map[string]any{{"dest-uuid": "t-hub", "type": "uses"}},
		})
	}
	writeCluster(t, clusters, "threat-actor", actors)
	writeCluster(t, clusters, "mitre-attack-pattern", []map[string]any{
		{"value": "Everyone Does This", "uuid": "t-hub"},
	})
	g, err := Load(root, "deadbeef")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	hub, _ := g.Node("t-hub")
	if hub.GroupCount != 14 {
		t.Fatalf("fixture broken: the hub has %d actors, want 14", hub.GroupCount)
	}

	// At depth 2 the bystanders sit one hop past the hub. If the walk goes
	// through it, A and B suddenly share twelve actors.
	cmp, ok := g.Compare("a-1", "b-1", CompareOpts{Depth: 2})
	if !ok {
		t.Fatal("expected a comparison")
	}
	if cmp.SharedCount != 0 {
		t.Errorf("nothing should be shared through a generic hub, got %d: %+v",
			cmp.SharedCount, cmp.Shared)
	}
	if cmp.Similarity != 0 {
		t.Errorf("similarity = %v, want 0", cmp.Similarity)
	}
}

func TestCompareUnknownEntries(t *testing.T) {
	g := compareGraph(t)
	if _, ok := g.Compare("a-1", "nope", CompareOpts{}); ok {
		t.Error("expected no comparison against an unknown uuid")
	}
	if _, ok := g.Compare("nope", "b-1", CompareOpts{}); ok {
		t.Error("expected no comparison from an unknown uuid")
	}
}
