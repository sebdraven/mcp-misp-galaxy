package galaxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func draftGraph(t *testing.T) *Graph {
	t.Helper()
	root := t.TempDir()
	clusters := filepath.Join(root, "clusters")
	if err := os.MkdirAll(clusters, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeCluster(t, clusters, "threat-actor", []map[string]any{
		{"value": "MUSTANG PANDA", "uuid": "a-mustang", "meta": map[string]any{
			"synonyms": []string{"HoneyMyte", "Earth Preta"},
		}},
	})
	writeCluster(t, clusters, "tool", []map[string]any{
		{"value": "PlugX", "uuid": "t-plugx"},
		{"value": "ToneShell", "uuid": "t-toneshell"},
	})
	g, err := Load(root, "deadbeef")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return g
}

func TestDraftRefusesExistingName(t *testing.T) {
	// The check the tool exists for. Adding a name that is already in the
	// corpus is how alias proliferation happens, and it happens by omission
	// rather than by intent.
	g := draftGraph(t)
	res, err := g.DraftClusterEntry(DraftOpts{Name: "PlugX", Galaxy: "tool"})
	if err != nil {
		t.Fatalf("DraftClusterEntry: %v", err)
	}
	if !res.Refused {
		t.Error("an existing name must be refused")
	}
	if res.Entry != nil {
		t.Error("a refused draft must not hand back an entry to paste")
	}
	if len(res.Exact) != 1 || res.Exact[0].UUID != "t-plugx" {
		t.Errorf("the colliding entry should be named, got %+v", res.Exact)
	}
}

func TestDraftRefusesExistingSynonym(t *testing.T) {
	// A synonym collision is the one that gets missed: the name is not the
	// value of any entry, so a plain lookup finds nothing.
	g := draftGraph(t)
	res, err := g.DraftClusterEntry(DraftOpts{Name: "HoneyMyte", Galaxy: "tool"})
	if err != nil {
		t.Fatalf("DraftClusterEntry: %v", err)
	}
	if !res.Refused {
		t.Fatal("a name already used as a synonym must be refused")
	}
	if res.Exact[0].MatchedVia != "HoneyMyte" {
		t.Errorf("the collision should say which synonym matched, got %q",
			res.Exact[0].MatchedVia)
	}
	// And across galaxies: the collision is in threat-actor, the draft targets
	// tool. A reviewer would find it either way.
	if res.Exact[0].Galaxy != "threat-actor" {
		t.Errorf("collisions must be checked corpus-wide, got galaxy %q",
			res.Exact[0].Galaxy)
	}
}

func TestDraftReportsNearMissesWithoutBlocking(t *testing.T) {
	// Close names are frequently different entities, so they must not block —
	// but a reviewer will ask about them, so they come back with the draft.
	g := draftGraph(t)
	res, err := g.DraftClusterEntry(DraftOpts{Name: "ToneShel", Galaxy: "tool"})
	if err != nil {
		t.Fatalf("DraftClusterEntry: %v", err)
	}
	if res.Refused {
		t.Fatal("a near miss must not block the draft")
	}
	if res.Entry == nil {
		t.Fatal("expected an entry")
	}
	if len(res.Near) == 0 {
		t.Error("the near name should be reported")
	}
}

func TestDraftGeneratesValidUUID(t *testing.T) {
	g := draftGraph(t)
	res, err := g.DraftClusterEntry(DraftOpts{Name: "CoolClient", Galaxy: "tool"})
	if err != nil {
		t.Fatalf("DraftClusterEntry: %v", err)
	}
	if res.Entry == nil {
		t.Fatal("expected an entry")
	}
	v4 := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !v4.MatchString(res.Entry.UUID) {
		t.Errorf("uuid %q is not a lowercase v4", res.Entry.UUID)
	}

	// Two drafts must not collide.
	other, _ := g.DraftClusterEntry(DraftOpts{Name: "OtherClient", Galaxy: "tool"})
	if other.Entry.UUID == res.Entry.UUID {
		t.Error("two drafts produced the same uuid")
	}
}

func TestDraftRelationRequiresARealTarget(t *testing.T) {
	// Linking to a uuid that is not in the corpus would produce a dangling
	// relation — one of the 624 the loader already has to invent.
	g := draftGraph(t)
	if _, err := g.DraftClusterEntry(DraftOpts{
		Name: "CoolClient", Galaxy: "tool", UsedBy: "no-such-uuid",
	}); err == nil {
		t.Error("expected an error when the relation target does not exist")
	}
}

func TestDraftRelationDefaultsToCautiousConfidence(t *testing.T) {
	g := draftGraph(t)
	res, err := g.DraftClusterEntry(DraftOpts{
		Name: "CoolClient", Galaxy: "tool", UsedBy: "a-mustang",
	})
	if err != nil {
		t.Fatalf("DraftClusterEntry: %v", err)
	}
	if len(res.Entry.Related) != 1 {
		t.Fatalf("expected one relation, got %+v", res.Entry.Related)
	}
	rel := res.Entry.Related[0]
	if rel.Type != "used-by" {
		t.Errorf("relation type = %q, want used-by", rel.Type)
	}
	if !strings.Contains(rel.Tags[0], `="likely"`) {
		t.Errorf("the default confidence should be the cautious one, got %q", rel.Tags[0])
	}
}

func TestDraftRejectsUnknownConfidence(t *testing.T) {
	// The estimative-language vocabulary is fixed; an invented value would
	// pass schema validation as a string and mean nothing to a reader.
	g := draftGraph(t)
	if _, err := g.DraftClusterEntry(DraftOpts{
		Name: "CoolClient", Galaxy: "tool",
		UsedBy: "a-mustang", Confidence: "pretty-sure",
	}); err == nil {
		t.Error("expected an error for a confidence outside the vocabulary")
	}
}

func TestDraftJSONRoundTrips(t *testing.T) {
	// The block is meant to be pasted into a cluster file, so it has to parse
	// back as the corpus schema expects.
	g := draftGraph(t)
	res, _ := g.DraftClusterEntry(DraftOpts{
		Name: "CoolClient", Galaxy: "tool",
		Description: "A backdoor.",
		Refs:        []string{"https://example.invalid/report"},
		Date:        "August 2026.",
		UsedBy:      "a-mustang", Confidence: "almost-certain",
	})
	out, err := MarshalDraft(res.Entry)
	if err != nil {
		t.Fatalf("MarshalDraft: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal([]byte(out), &back); err != nil {
		t.Fatalf("the rendered entry does not parse: %v\n%s", err, out)
	}
	for _, key := range []string{"description", "meta", "related", "uuid", "value"} {
		if _, ok := back[key]; !ok {
			t.Errorf("rendered entry is missing %q", key)
		}
	}
}

func TestDraftRequiresNameAndGalaxy(t *testing.T) {
	g := draftGraph(t)
	if _, err := g.DraftClusterEntry(DraftOpts{Galaxy: "tool"}); err == nil {
		t.Error("expected an error without a name")
	}
	if _, err := g.DraftClusterEntry(DraftOpts{Name: "Whatever"}); err == nil {
		t.Error("expected an error without a target galaxy")
	}
}
