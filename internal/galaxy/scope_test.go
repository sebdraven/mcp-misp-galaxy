package galaxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// writeGalaxyDef drops one galaxy definition into dir. Empty category and
// subCategory are left out of the file, as in a corpus that predates them.
func writeGalaxyDef(t *testing.T, dir, galaxyType, category, subCategory string) {
	t.Helper()
	body := map[string]any{
		"type":        galaxyType,
		"name":        galaxyType + " definition",
		"uuid":        galaxyType + "-def-uuid",
		"description": galaxyType + " described",
		"namespace":   "misp",
		"version":     1,
	}
	if category != "" {
		body["category"] = category
	}
	if subCategory != "" {
		body["sub_category"] = subCategory
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshalling fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, galaxyType+".json"), raw, 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
}

// categorisedGraph holds two categorised galaxies and one whose definition
// declares no category.
func categorisedGraph(t *testing.T) *Graph {
	t.Helper()
	root := t.TempDir()
	clusters := filepath.Join(root, "clusters")
	galaxies := filepath.Join(root, "galaxies")
	for _, d := range []string{clusters, galaxies} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	writeCluster(t, clusters, "threat-actor", []map[string]any{
		{"value": "Fancy", "uuid": "ta-1"},
	})
	writeCluster(t, clusters, "malpedia", []map[string]any{
		{"value": "Zebrocy", "uuid": "mp-1"},
	})
	writeCluster(t, clusters, "firearms", []map[string]any{
		{"value": "Fancy", "uuid": "fa-1"},
	})
	writeGalaxyDef(t, galaxies, "threat-actor", "named-threat", "actor")
	writeGalaxyDef(t, galaxies, "malpedia", "named-threat", "malware")
	writeGalaxyDef(t, galaxies, "firearms", "", "")

	g, err := Load(root, "deadbeef")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return g
}

func inventoryOf(g *Graph) map[string]GalaxyInfo {
	out := map[string]GalaxyInfo{}
	for _, info := range g.Galaxies() {
		out[info.Type] = info
	}
	return out
}

func TestGalaxyDefsCarryCategory(t *testing.T) {
	inv := inventoryOf(categorisedGraph(t))
	if got := inv["threat-actor"]; got.Category != "named-threat" || got.SubCategory != "actor" {
		t.Errorf("threat-actor = %+v, want named-threat / actor", got)
	}
	if got := inv["malpedia"]; got.Category != "named-threat" || got.SubCategory != "malware" {
		t.Errorf("malpedia = %+v, want named-threat / malware", got)
	}
	if got := inv["firearms"]; got.Category != "" || got.SubCategory != "" {
		t.Errorf("firearms declares no category, got %+v", got)
	}
	if got := inv["firearms"]; got.Name != "firearms definition" {
		t.Errorf("an uncategorised definition must still enrich the inventory, got %+v", got)
	}
}

func TestGalaxyCategoryEmptyWithoutDefinitions(t *testing.T) {
	for _, info := range chainGraph(t).Galaxies() {
		if info.Category != "" || info.SubCategory != "" {
			t.Errorf("galaxy %q has no definition, got %+v", info.Type, info)
		}
	}
}

func TestExpandScopeSelectors(t *testing.T) {
	g := categorisedGraph(t)
	cases := []struct {
		in   []string
		want []string
	}{
		{[]string{"category:named-threat"}, []string{"malpedia", "threat-actor"}},
		{[]string{"sub_category:actor"}, []string{"threat-actor"}},
		{[]string{"Sub_Category:Malware"}, []string{"malpedia"}},
		{[]string{"firearms", "sub_category:actor"}, []string{"firearms", "threat-actor"}},
		{[]string{"malpedia", "category:named-threat"}, []string{"malpedia", "threat-actor"}},
		{[]string{"threat-actor"}, []string{"threat-actor"}},
		{nil, nil},
	}
	for _, c := range cases {
		got, unresolved := g.ExpandScope(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("ExpandScope(%q) = %q, want %q", c.in, got, c.want)
		}
		if len(unresolved) != 0 {
			t.Errorf("ExpandScope(%q) unresolved = %q, want none", c.in, unresolved)
		}
	}
}

func TestExpandScopeReportsUnresolved(t *testing.T) {
	g := categorisedGraph(t)
	got, unresolved := g.ExpandScope([]string{"category:victim", "sub_category:", "nope", "malpedia"})
	if want := []string{"category:victim", "sub_category:", "nope"}; !reflect.DeepEqual(unresolved, want) {
		t.Errorf("unresolved = %q, want %q", unresolved, want)
	}
	if want := []string{"category:victim", "sub_category:", "nope", "malpedia"}; !reflect.DeepEqual(got, want) {
		t.Errorf("scope = %q, want %q", got, want)
	}
}

func TestUnresolvedSelectorDoesNotWidenScope(t *testing.T) {
	g := categorisedGraph(t)
	scope, _ := g.ExpandScope([]string{"category:victim"})
	if got := g.Resolve("Fancy", scope, 10); len(got) != 0 {
		t.Errorf("a selector matching nothing must search nothing, got %+v", got)
	}
}

func TestSelectorScopesResolution(t *testing.T) {
	g := categorisedGraph(t)
	scope, _ := g.ExpandScope([]string{"category:named-threat"})
	got := g.Resolve("Fancy", scope, 10)
	if len(got) != 1 || got[0].UUID != "ta-1" {
		t.Fatalf("expected only the threat-actor entry, got %+v", got)
	}
}

func TestIsScopeSelector(t *testing.T) {
	cases := map[string]bool{
		"category:named-threat": true,
		" sub_category:actor":   true,
		"SUB_CATEGORY:actor":    true,
		"threat-actor":          false,
		"namespace:misp":        false,
		"all":                   false,
	}
	for in, want := range cases {
		if got := IsScopeSelector(in); got != want {
			t.Errorf("IsScopeSelector(%q) = %v, want %v", in, got, want)
		}
	}
}
