package galaxy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// cooccurrenceGraph models the case the measure exists for: two techniques
// used by the same actors, and a third used by a different set.
//
// Six actors all use t-link and t-file; three of them also use t-apart, which
// two other actors use as well. So the first pair overlaps completely and the
// others only partly.
func cooccurrenceGraph(t *testing.T) *Graph {
	t.Helper()
	root := t.TempDir()
	clusters := filepath.Join(root, "clusters")
	if err := os.MkdirAll(clusters, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	var actors []map[string]any
	for i := 0; i < 6; i++ {
		rel := []map[string]any{
			{"dest-uuid": "t-link", "type": "uses"},
			{"dest-uuid": "t-file", "type": "uses"},
			{"dest-uuid": "m-1", "type": "uses"},
		}
		if i < 3 {
			rel = append(rel, map[string]any{"dest-uuid": "t-apart", "type": "uses"})
		}
		actors = append(actors, map[string]any{
			"value": fmt.Sprintf("Actor %d", i), "uuid": fmt.Sprintf("a-%d", i),
			"related": rel,
		})
	}
	// Two more actors use t-apart but nothing else in the malware's profile.
	for i := 6; i < 8; i++ {
		actors = append(actors, map[string]any{
			"value": fmt.Sprintf("Actor %d", i), "uuid": fmt.Sprintf("a-%d", i),
			"related": []map[string]any{{"dest-uuid": "t-apart", "type": "uses"}},
		})
	}
	writeCluster(t, clusters, "threat-actor", actors)

	writeCluster(t, clusters, "mitre-malware", []map[string]any{
		{"value": "Family", "uuid": "m-1", "related": []map[string]any{
			{"dest-uuid": "t-link", "type": "uses"},
			{"dest-uuid": "t-file", "type": "uses"},
			{"dest-uuid": "t-apart", "type": "uses"},
		}},
	})
	writeCluster(t, clusters, "mitre-attack-pattern", []map[string]any{
		{"value": "Malicious Link", "uuid": "t-link"},
		{"value": "Malicious File", "uuid": "t-file"},
		{"value": "Something Else", "uuid": "t-apart"},
	})

	g, err := Load(root, "deadbeef")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return g
}

func TestCoOccurrenceFindsIdenticalActorSets(t *testing.T) {
	g := cooccurrenceGraph(t)

	// The fixture only tests anything if the sets really differ.
	link, _ := g.Node("t-link")
	apart, _ := g.Node("t-apart")
	if link.GroupCount != 6 || apart.GroupCount != 5 {
		t.Fatalf("fixture broken: link=%d apart=%d, want 6 and 5",
			link.GroupCount, apart.GroupCount)
	}

	pairs := g.CoOccurrence("m-1", CoOccurrenceThreshold, 10)
	if len(pairs) != 1 {
		t.Fatalf("expected exactly the fully-overlapping pair, got %+v", pairs)
	}
	if pairs[0].Rate != 1.0 {
		t.Errorf("rate = %v, want 1.0 for identical actor sets", pairs[0].Rate)
	}
	if pairs[0].Shared != 6 {
		t.Errorf("shared = %d, want 6", pairs[0].Shared)
	}
}

func TestCoOccurrenceDividesByLargerSet(t *testing.T) {
	// Dividing by the larger set is stricter than Jaccard: a small set nested
	// inside a big one must not score as though the two were equivalent.
	// t-apart (5 actors) shares 3 with t-link (6), so 3/6 = 0.5, not 3/5.
	g := cooccurrenceGraph(t)
	pairs := g.CoOccurrence("m-1", 0.1, 10)

	var found bool
	for _, p := range pairs {
		if (p.AUUID == "t-apart" && p.BUUID == "t-link") ||
			(p.AUUID == "t-link" && p.BUUID == "t-apart") {
			found = true
			if p.Rate != 0.5 {
				t.Errorf("rate = %v, want 0.5 (3 shared over the larger set of 6)", p.Rate)
			}
		}
	}
	if !found {
		t.Fatalf("expected the partial pair at a low threshold, got %+v", pairs)
	}
}

func TestCoOccurrenceIgnoresActorsAsCandidates(t *testing.T) {
	// The measure is over behaviours co-observed across actors. An actor is
	// not a behaviour, and pairing two actors would answer a different
	// question entirely.
	g := cooccurrenceGraph(t)
	for _, p := range g.CoOccurrence("a-0", 0.1, 50) {
		for _, uuid := range []string{p.AUUID, p.BUUID} {
			if n, ok := g.Node(uuid); ok && ActorGalaxies[n.Galaxy] {
				t.Errorf("an actor should never appear as a co-occurrence candidate: %s", uuid)
			}
		}
	}
}

func TestCoOccurrenceSkipsEntriesWithNoActors(t *testing.T) {
	// The rate is undefined over empty sets; such entries must be dropped
	// rather than scored as 0, which would suggest they were compared.
	root := t.TempDir()
	clusters := filepath.Join(root, "clusters")
	if err := os.MkdirAll(clusters, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeCluster(t, clusters, "mitre-malware", []map[string]any{
		{"value": "Family", "uuid": "m-1", "related": []map[string]any{
			{"dest-uuid": "t-a", "type": "uses"},
			{"dest-uuid": "t-b", "type": "uses"},
		}},
	})
	writeCluster(t, clusters, "mitre-attack-pattern", []map[string]any{
		{"value": "A", "uuid": "t-a"},
		{"value": "B", "uuid": "t-b"},
	})
	g, err := Load(root, "deadbeef")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if pairs := g.CoOccurrence("m-1", 0.1, 10); len(pairs) != 0 {
		t.Errorf("entries with no actors cannot co-occur, got %+v", pairs)
	}
}

func TestCoOccurrenceUnknownUUID(t *testing.T) {
	g := cooccurrenceGraph(t)
	if pairs := g.CoOccurrence("nope", CoOccurrenceThreshold, 10); pairs != nil {
		t.Errorf("expected nothing for an unknown uuid, got %+v", pairs)
	}
}

func TestCoOccurrenceAtZeroRateReportsEveryOverlap(t *testing.T) {
	// 0 is a legitimate threshold, not a stand-in for "use the default": it
	// means "show every overlap". The service keeps the two apart with a
	// pointer, and this checks the graph honours the value it is given.
	g := cooccurrenceGraph(t)
	all := g.CoOccurrence("m-1", 0, 50)
	strict := g.CoOccurrence("m-1", CoOccurrenceThreshold, 50)
	if len(all) <= len(strict) {
		t.Errorf("a zero threshold should report more pairs than %v, got %d",
			CoOccurrenceThreshold, len(all))
	}
}
