package galaxy

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// Graph is an immutable view of the MISP galaxy corpus. Every method is safe
// for concurrent use because nothing mutates after Load returns.
type Graph struct {
	nodes      map[string]*Node // by UUID
	index      map[string][]*Node
	byGalaxy   map[string][]*Node
	galaxies   map[string]GalaxyInfo
	thresholds map[string]int // per-galaxy generic cut-off
	stats      Stats
}

// Holder carries the live graph and lets a reload swap it without locking
// readers. Callers take the current graph once per request and keep using it;
// a swap mid-request is harmless, the old graph stays valid.
type Holder struct {
	current atomic.Pointer[Graph]
}

// Get returns the live graph, or nil before the first successful load.
func (h *Holder) Get() *Graph { return h.current.Load() }

// Set publishes a new graph.
func (h *Holder) Set(g *Graph) { h.current.Store(g) }

// ProgressFunc receives load progress: a phase name, how many units are done
// and how many there are in total. A total of 0 means the phase size is not
// known ahead of time.
//
// The loader knows nothing about terminals or formatting — it reports, the
// caller renders.
type ProgressFunc func(phase string, done, total int)

// LoadOption configures Load.
type LoadOption func(*loadOpts)

type loadOpts struct {
	progress ProgressFunc
}

// WithProgress attaches a progress callback.
func WithProgress(fn ProgressFunc) LoadOption {
	return func(o *loadOpts) { o.progress = fn }
}

// Load reads clusters/ and galaxies/ under root (the misp-galaxy checkout) and
// builds a graph. sourceRef is recorded in the stats for provenance — pass the
// submodule commit so a result can always be traced back to a corpus state.
func Load(root, sourceRef string, opts ...LoadOption) (*Graph, error) {
	var o loadOpts
	for _, fn := range opts {
		fn(&o)
	}
	report := o.progress
	if report == nil {
		report = func(string, int, int) {}
	}

	clusterDir := filepath.Join(root, "clusters")
	if _, err := os.Stat(clusterDir); err != nil {
		return nil, fmt.Errorf("galaxy: no clusters/ under %s: %w", root, err)
	}

	g := &Graph{
		nodes:    make(map[string]*Node, 1<<16),
		index:    make(map[string][]*Node, 1<<16),
		byGalaxy: make(map[string][]*Node),
		galaxies: make(map[string]GalaxyInfo),
	}

	files, err := jsonFiles(clusterDir)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("galaxy: clusters/ under %s holds no JSON", root)
	}

	// Pass 1 — every value becomes a node. Edges are held aside because a
	// dest-uuid routinely points at a value defined in a file we have not read
	// yet; wiring as we go would manufacture dangling nodes that are not.
	type pending struct {
		from string
		rel  []relatedEntry
	}
	var deferred []pending

	for i, path := range files {
		report("clusters", i, len(files))
		cf, err := readCluster(path)
		if err != nil {
			return nil, err
		}
		gtype := cf.Type
		if gtype == "" {
			// Fall back to the filename: a handful of clusters omit "type".
			gtype = strings.TrimSuffix(filepath.Base(path), ".json")
		}
		if _, seen := g.galaxies[gtype]; !seen {
			g.galaxies[gtype] = GalaxyInfo{Type: gtype, Name: cf.Name, Description: cf.Description}
		}

		for _, v := range cf.Values {
			if v.Value == "" {
				continue // nothing to name it by, and nothing to search for
			}
			// The corpus schema only requires "value": roughly 400 entries carry
			// no uuid. Skipping them dropped them from the search index too,
			// since the index is built from the node map — a silent data loss.
			// They get a synthetic key instead: searchable, but unreachable by
			// any relation, since nothing can declare a dest-uuid for them.
			key, synthetic := v.UUID, false
			if key == "" {
				key, synthetic = syntheticKey(gtype, v.Value), true
			}
			n, exists := g.nodes[key]
			if exists && !n.Dangling {
				// Same key defined twice. Keep the first and move on rather
				// than silently overwriting one definition with another.
				continue
			}
			if !exists {
				n = &Node{UUID: key}
				g.nodes[key] = n
			}
			n.Value = v.Value
			n.Galaxy = gtype
			n.Description = v.Description
			n.Meta = v.Meta
			n.Revoked = v.Revoked
			n.Synthetic = synthetic
			n.Synonyms = synonymsOf(v.Meta)
			n.Dangling = false

			g.byGalaxy[gtype] = append(g.byGalaxy[gtype], n)
			if len(v.Related) > 0 {
				deferred = append(deferred, pending{from: key, rel: v.Related})
			}
		}
	}
	report("clusters", len(files), len(files))

	// Pass 2 — merge the declarations into one link per pair. The corpus often
	// declares the same relation from both sides, and sometimes under more than
	// one type; counting those repetitions is what gives an edge its confidence.
	type linkInfo struct {
		confidence int
		firstType  string
		types      []string
	}
	links := make(map[[2]string]*linkInfo)
	for i, p := range deferred {
		if i%512 == 0 {
			report("relations", i, len(deferred))
		}
		for _, rel := range p.rel {
			if rel.DestUUID == "" || rel.DestUUID == p.from {
				continue
			}
			if _, ok := g.nodes[rel.DestUUID]; !ok {
				g.nodes[rel.DestUUID] = &Node{UUID: rel.DestUUID, Dangling: true}
			}
			// Canonical unordered key: a link declared A→B and B→A is one
			// link asserted twice, not two links.
			key := pairKey(p.from, rel.DestUUID)
			info := links[key]
			if info == nil {
				info = &linkInfo{firstType: rel.Type}
				links[key] = info
			}
			info.confidence++
			if rel.Type != "" && !containsString(info.types, rel.Type) {
				info.types = append(info.types, rel.Type)
			}
		}
	}
	report("relations", len(deferred), len(deferred))

	// Materialise one edge per *declared* direction, all sharing the merged
	// link's confidence and types.
	//
	// Collapsing a two-way link into a single oriented edge would make Out and
	// In depend on which cluster file happened to be read first, so an Out-only
	// traversal could hide a relation the node genuinely declares. Direction has
	// to keep reflecting what the corpus stated, not what the loader saw first.
	materialised := make(map[[2]string]bool, len(links))
	for _, p := range deferred {
		for _, rel := range p.rel {
			if rel.DestUUID == "" || rel.DestUUID == p.from {
				continue
			}
			directed := [2]string{p.from, rel.DestUUID}
			if materialised[directed] {
				continue // same direction declared twice
			}
			materialised[directed] = true

			info := links[pairKey(p.from, rel.DestUUID)]
			sort.Strings(info.types)
			from, to := g.nodes[p.from], g.nodes[rel.DestUUID]
			edge := Edge{
				Type: info.firstType, Types: info.types, Confidence: info.confidence,
			}
			edge.To = to
			from.Out = append(from.Out, edge)
			edge.To = from
			to.In = append(to.In, edge)
		}
	}
	edges := len(links)

	report("index", 0, len(g.nodes))
	g.buildIndex()
	report("index", len(g.nodes), len(g.nodes))
	g.loadGalaxyDefs(filepath.Join(root, "galaxies"))
	bridges := g.markBridges()
	g.countGroups()
	g.thresholds = g.genericThresholds()

	dangling, revoked, synthetic := 0, 0, 0
	for _, n := range g.nodes {
		if n.Dangling {
			dangling++
		}
		if n.Revoked {
			revoked++
		}
		if n.Synthetic {
			synthetic++
		}
	}
	for gt, ns := range g.byGalaxy {
		info := g.galaxies[gt]
		info.Type, info.Nodes = gt, len(ns)
		g.galaxies[gt] = info
	}

	g.stats = Stats{
		Nodes:       len(g.nodes),
		Edges:       edges,
		Bridges:     bridges,
		Dangling:    dangling,
		Revoked:     revoked,
		Synthetic:   synthetic,
		Galaxies:    len(g.galaxies),
		IndexedKeys: len(g.index),
		SourceRef:   sourceRef,
		LoadedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	return g, nil
}

// Stats returns the summary computed at load time.
func (g *Graph) Stats() Stats { return g.stats }

// Node returns the node for a UUID.
func (g *Graph) Node(uuid string) (*Node, bool) {
	n, ok := g.nodes[uuid]
	return n, ok
}

// Galaxies lists the galaxies present in the checkout, sorted by type.
// Galaxies with no entries are omitted: the corpus keeps a handful of
// deprecated MITRE cluster files whose values array is empty, and listing them
// as available is misleading.
func (g *Graph) Galaxies() []GalaxyInfo {
	out := make([]GalaxyInfo, 0, len(g.galaxies))
	for _, info := range g.galaxies {
		if info.Nodes == 0 {
			continue
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// HasGalaxy reports whether a galaxy type exists and holds entries. Used to
// tell a typo in a scope from a galaxy that is genuinely absent.
func (g *Graph) HasGalaxy(t string) bool {
	for gt, info := range g.galaxies {
		if strings.EqualFold(gt, t) && info.Nodes > 0 {
			return true
		}
	}
	return false
}

// syntheticKeyPrefix marks an identifier this loader invented rather than read
// from the corpus. The separator cannot occur in a UUID, so a synthetic key can
// never collide with a real one or be hit by a dest-uuid lookup.
const syntheticKeyPrefix = "synthetic::"

func syntheticKey(galaxyType, value string) string {
	return syntheticKeyPrefix + galaxyType + "::" + value
}

// countGroups records, for every node, how many distinct threat actors are
// linked to it.
//
// This is the specificity signal: an entry linked to one actor can serve as a
// behavioural signature, one linked to dozens cannot. Distinct actors, not
// distinct edges — a link declared from both sides is one actor, not two.
func (g *Graph) countGroups() {
	for _, n := range g.nodes {
		seen := make(map[*Node]bool)
		for _, e := range undirectedEdges(n) {
			if e.To == n || seen[e.To] {
				continue
			}
			if ActorGalaxies[strings.ToLower(e.To.Galaxy)] {
				seen[e.To] = true
			}
		}
		n.GroupCount = len(seen)
	}
}

// GenericEntry is one entry ranked by how many actors are linked to it.
//
// A type of its own rather than reusing Candidate: a resolver candidate
// carries why it matched a query, and there is no query here. Reporting an
// empty reason and a score of zero would invite a caller to read meaning into
// fields that never applied.
type GenericEntry struct {
	UUID       string `json:"uuid"`
	Tag        string `json:"tag,omitempty"`
	Value      string `json:"value"`
	Galaxy     string `json:"galaxy"`
	GroupCount int    `json:"group_count" jsonschema:"distinct threat actors linked to this entry"`
	Degree     int    `json:"degree"`
}

// MostGeneric returns the entries of a galaxy linked to the most threat
// actors, worst offenders first.
//
// Useful before reading any list of relations: these are the entries to
// discount, because their presence says nothing about who was behind an
// intrusion. An empty galaxyType looks across the whole corpus.
func (g *Graph) MostGeneric(galaxyType string, limit int) []GenericEntry {
	if limit <= 0 {
		limit = 10
	}
	var out []GenericEntry
	for _, n := range g.nodes {
		if n.Dangling || n.GroupCount == 0 {
			continue
		}
		if galaxyType != "" && !strings.EqualFold(n.Galaxy, galaxyType) {
			continue
		}
		out = append(out, GenericEntry{
			UUID: n.UUID, Tag: n.Tag(), Value: n.Value, Galaxy: n.Galaxy,
			GroupCount: n.GroupCount, Degree: len(n.Out) + len(n.In),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].GroupCount != out[j].GroupCount {
			return out[i].GroupCount > out[j].GroupCount
		}
		return out[i].Value < out[j].Value
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// GenericPercentile is the share of a galaxy's entries that are NOT considered
// generic. An entry lands above it when more actors are linked to it than to
// 90% of its galaxy.
//
// Relative rather than fixed, because the galaxies are not comparable: the
// busiest ATT&CK techniques are linked to 30-60 actors while a whole galaxy of
// malware families may top out at 3. A single cut-off marks almost everything
// generic in one and nothing in the other.
//
// The cost is that an entry can become generic without changing, because the
// corpus moved around it. That is why the threshold it was judged against is
// reported alongside the flag rather than left implicit.
const GenericPercentile = 0.90

// minGenericSample is how many attributed entries a galaxy needs before a
// percentile means anything. Below it, the fixed fallback applies.
//
// A 90th percentile over three values is the third value — it describes that
// handful of entries, not a distribution, and would label as generic whatever
// happens to sit at the top of a nearly empty galaxy.
const minGenericSample = 10

// genericThresholds computes, per galaxy, the group_count above which an entry
// counts as generic.
//
// Entries with no actor at all are excluded from the distribution: they say
// nothing about how widely shared a galaxy's entries are, and including them
// would drag every threshold down to zero in the many galaxies where most
// entries are unattributed.
func (g *Graph) genericThresholds() map[string]int {
	counts := map[string][]int{}
	for _, n := range g.nodes {
		if n.Dangling || n.GroupCount == 0 {
			continue
		}
		key := strings.ToLower(n.Galaxy)
		counts[key] = append(counts[key], n.GroupCount)
	}

	out := make(map[string]int, len(counts))
	for galaxyType, values := range counts {
		if len(values) < minGenericSample {
			continue // too few entries for a percentile to describe anything
		}
		sort.Ints(values)
		idx := int(float64(len(values)) * GenericPercentile)
		if idx >= len(values) {
			idx = len(values) - 1
		}
		threshold := values[idx]
		// A threshold of 1 would mark as generic every entry linked to a single
		// actor, which is the most discriminating case there is. Floor it.
		if threshold < 2 {
			threshold = 2
		}
		out[galaxyType] = threshold
	}
	return out
}

// GenericThreshold returns the group_count above which an entry of this galaxy
// is treated as generic, and whether the galaxy had enough attributed entries
// to compute one.
func (g *Graph) GenericThreshold(galaxyType string) (int, bool) {
	t, ok := g.thresholds[strings.ToLower(galaxyType)]
	return t, ok
}

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// markBridges finds the links whose removal would increase the number of
// connected components, and flags them on both directions of each edge.
//
// This matters because a single wrong assertion can fuse two unrelated
// clusters: in the threat-actor naming literature, removing one such link from
// the largest alias cluster cut the number of implied alias pairs by about a
// third. A bridge with a confidence of 1 is the shape of that mistake, and
// flagging it lets a caller treat the join as provisional rather than as fact.
//
// Iterative Tarjan rather than recursive: the corpus has chains long enough
// that recursion depth becomes a needless risk.
func (g *Graph) markBridges() int {
	type frame struct {
		node   *Node
		parent *Node
		idx    int
		edges  []Edge
	}

	disc := make(map[*Node]int, len(g.nodes))
	low := make(map[*Node]int, len(g.nodes))
	bridgeSet := make(map[[2]string]bool)
	timer := 0

	for _, root := range g.nodes {
		if _, seen := disc[root]; seen {
			continue
		}
		timer++
		disc[root], low[root] = timer, timer
		stack := []frame{{node: root, edges: undirectedEdges(root)}}

		for len(stack) > 0 {
			top := &stack[len(stack)-1]
			if top.idx < len(top.edges) {
				e := top.edges[top.idx]
				top.idx++
				if e.To == top.parent {
					// Skip the edge back to the parent once. A second edge to
					// the same node would be a genuine cycle, but merged links
					// mean that cannot happen here.
					continue
				}
				if d, seen := disc[e.To]; seen {
					if d < low[top.node] {
						low[top.node] = d
					}
					continue
				}
				timer++
				disc[e.To], low[e.To] = timer, timer
				stack = append(stack, frame{node: e.To, parent: top.node, edges: undirectedEdges(e.To)})
				continue
			}

			done := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if done.parent == nil {
				continue
			}
			if low[done.node] < low[done.parent] {
				low[done.parent] = low[done.node]
			}
			if low[done.node] > disc[done.parent] {
				bridgeSet[pairKey(done.parent.UUID, done.node.UUID)] = true
			}
		}
	}

	for _, n := range g.nodes {
		for i := range n.Out {
			if bridgeSet[pairKey(n.UUID, n.Out[i].To.UUID)] {
				n.Out[i].Bridge = true
			}
		}
		for i := range n.In {
			if bridgeSet[pairKey(n.UUID, n.In[i].To.UUID)] {
				n.In[i].Bridge = true
			}
		}
	}
	return len(bridgeSet)
}

func pairKey(a, b string) [2]string {
	if a > b {
		a, b = b, a
	}
	return [2]string{a, b}
}

func undirectedEdges(n *Node) []Edge {
	if len(n.In) == 0 {
		return n.Out
	}
	if len(n.Out) == 0 {
		return n.In
	}
	all := make([]Edge, 0, len(n.Out)+len(n.In))
	return append(append(all, n.Out...), n.In...)
}

// ---- loading helpers --------------------------------------------------------

func jsonFiles(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.EqualFold(filepath.Ext(path), ".json") {
			out = append(out, path)
		}
		return nil
	})
	sort.Strings(out) // deterministic: decides which duplicate UUID wins
	return out, err
}

func readCluster(path string) (*clusterFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("galaxy: reading %s: %w", path, err)
	}
	var cf clusterFile
	if err := json.Unmarshal(raw, &cf); err != nil {
		return nil, fmt.Errorf("galaxy: parsing %s: %w", path, err)
	}
	return &cf, nil
}

// loadGalaxyDefs enriches the galaxy inventory with the definitions under
// galaxies/. Absent or unreadable definitions are not fatal: the cluster files
// alone are enough to build the graph.
func (g *Graph) loadGalaxyDefs(dir string) {
	files, err := jsonFiles(dir)
	if err != nil {
		return
	}
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var gf galaxyFile
		if json.Unmarshal(raw, &gf) != nil || gf.Type == "" {
			continue
		}
		info, ok := g.galaxies[gf.Type]
		if !ok {
			continue // a galaxy with no cluster in this checkout
		}
		info.Name, info.Namespace = gf.Name, gf.Namespace
		if gf.Description != "" {
			info.Description = gf.Description
		}
		g.galaxies[gf.Type] = info
	}
}

func synonymsOf(meta json.RawMessage) []string {
	if len(meta) == 0 {
		return nil
	}
	var mb metaBlock
	if json.Unmarshal(meta, &mb) != nil {
		return nil
	}
	return mb.Synonyms
}
