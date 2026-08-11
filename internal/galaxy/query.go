package galaxy

import (
	"sort"
	"strings"
)

// Direction selects which way traversal follows edges.
//
// Default is Both, and that is not a convenience: in this corpus a relation is
// usually declared on one side only, so following outgoing edges alone silently
// hides half the neighbourhood.
type Direction string

const (
	Both Direction = "both"
	Out  Direction = "out"
	In   Direction = "in"
)

// Neighbour is one node reached from a starting point.
type Neighbour struct {
	UUID             string   `json:"uuid"`
	Tag              string   `json:"tag,omitempty" jsonschema:"canonical MISP galaxy tag for this entry"`
	Value            string   `json:"value,omitempty"`
	Galaxy           string   `json:"galaxy,omitempty"`
	Depth            int      `json:"depth"`
	Via              string   `json:"via" jsonschema:"type of the relation on the last hop"`
	Confidence       int      `json:"confidence" jsonschema:"how many declarations back the last hop; 1 means a single unconfirmed assertion"`
	GroupCount       int      `json:"group_count" jsonschema:"how many distinct threat actors are linked to this entry. 1 is the strongest attribution signal: only this actor is known to use it. 0 means NO actor is linked at all — absence of data, not exclusivity, so it supports nothing. 0 is also normal on an actor entry, which is never counted against itself"`
	Generic          bool     `json:"generic,omitempty" jsonschema:"linked to more actors than 90% of its own galaxy, so it carries no attribution value on its own"`
	GenericThreshold int      `json:"generic_threshold,omitempty" jsonschema:"the group_count above which an entry of this galaxy is treated as generic. Galaxies differ enormously, so this is derived per galaxy rather than fixed"`
	Bridge           bool     `json:"bridge,omitempty" jsonschema:"the last hop is the only link joining these two parts of the graph. A bridge with confidence 1 rests on one unverified assertion and should be treated as provisional"`
	FromUUID         string   `json:"from_uuid" jsonschema:"node this one was reached from"`
	Dangling         bool     `json:"dangling,omitempty" jsonschema:"referenced by a relation but not defined in this checkout"`
	Path             []string `json:"path,omitempty" jsonschema:"uuids from the origin to this node, when requested"`
}

// NeighbourOpts tunes a traversal.
//
// Note that the service-level galaxy scope does NOT apply here, and that is
// deliberate: searching a name across unrelated taxonomies is noise, but
// following a relation someone declared is never noise — the arc exists
// because a human asserted it. Narrowing a traversal is done explicitly with
// Galaxies.
type NeighbourOpts struct {
	Depth     int       // hops, default 1
	Direction Direction // default Both
	EdgeTypes []string  // keep only these relation types; empty keeps all
	Galaxies  []string  // keep only entries from these galaxy types; empty keeps all

	// MaxGroupCount drops entries linked to more than this many threat actors:
	// the generic behaviours every group shares, which therefore distinguish
	// none of them. Unlike Galaxies, this blocks traversal as well as reporting.
	MaxGroupCount int

	Limit      int  // max nodes returned, default 200
	WithPaths  bool // record the route to each node
	SkipGhosts bool // drop dangling nodes from the result
}

// GenericThreshold is the fixed fallback used when a galaxy has too few
// attributed entries to derive one from its own distribution.
const GenericThreshold = 10

// neighbourRank orders neighbours by what they are, before how specific they
// are.
//
// Walking out from a malware, the actor using it is almost always what the
// caller came for, and burying it among two dozen undocumented techniques
// helps nobody. Sorting on group_count alone did exactly that: an actor scores
// 0 by construction and landed in the same bucket as techniques nobody is
// recorded as using.
func neighbourRank(n Neighbour) int {
	switch {
	case ActorGalaxies[strings.ToLower(n.Galaxy)]:
		return 0
	case n.Dangling:
		// Nothing is known about these beyond the fact that something points
		// at them; last, whatever else they carry.
		return 3
	case n.GroupCount > 0:
		// Attributed: an actual signal, ordered by specificity below.
		return 1
	default:
		// Reachable but linked to no actor — absence of data, not exclusivity.
		return 2
	}
}

// Neighbours walks outward from a node, breadth first, and returns what it
// reached. Nodes are reported at the shallowest depth they were found at.
func (g *Graph) Neighbours(uuid string, opt NeighbourOpts) []Neighbour {
	start, ok := g.nodes[uuid]
	if !ok {
		return nil
	}
	if opt.Depth <= 0 {
		opt.Depth = 1
	}
	if opt.Limit <= 0 {
		opt.Limit = 200
	}
	if opt.Direction == "" {
		opt.Direction = Both
	}
	keep := edgeFilter(opt.EdgeTypes)
	inScope := scopeSet(opt.Galaxies)

	type entry struct {
		node  *Node
		depth int
		path  []string
	}
	visited := map[*Node]bool{start: true}
	queue := []entry{{node: start, depth: 0, path: []string{start.UUID}}}
	var out []Neighbour

	for len(queue) > 0 && len(out) < opt.Limit {
		cur := queue[0]
		queue = queue[1:]
		if cur.depth == opt.Depth {
			continue
		}
		for _, e := range edgesOf(cur.node, opt.Direction) {
			ok, via := e.matches(keep)
			if !ok || visited[e.To] {
				continue
			}
			// Generic entries block the walk rather than merely being hidden
			// from it — the opposite of the galaxy filter below, and
			// deliberately so. A technique shared by dozens of actors is a hub:
			// routing through it connects everything to everything, which
			// manufactures adjacency that means nothing. A galaxy outside the
			// filter is just uninteresting to report; a generic node is
			// actively misleading to travel through.
			if opt.MaxGroupCount > 0 && e.To.GroupCount > opt.MaxGroupCount {
				continue
			}
			visited[e.To] = true

			path := append(append([]string(nil), cur.path...), e.To.UUID)
			queue = append(queue, entry{node: e.To, depth: cur.depth + 1, path: path})

			if e.To.Dangling && opt.SkipGhosts {
				continue
			}
			if opt.Galaxies != nil && inScope != nil && !inScope[strings.ToLower(e.To.Galaxy)] {
				continue
			}
			threshold, ok := g.GenericThreshold(e.To.Galaxy)
			if !ok {
				threshold = GenericThreshold
			}
			n := Neighbour{
				UUID: e.To.UUID, Tag: e.To.Tag(), Value: e.To.Value, Galaxy: e.To.Galaxy,
				Depth: cur.depth + 1, Via: via,
				Confidence: e.Confidence, Bridge: e.Bridge,
				GroupCount:       e.To.GroupCount,
				Generic:          e.To.GroupCount > threshold,
				GenericThreshold: threshold,
				FromUUID:         cur.node.UUID, Dangling: e.To.Dangling,
			}
			if opt.WithPaths {
				n.Path = path
			}
			out = append(out, n)
			if len(out) >= opt.Limit {
				break
			}
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Depth != out[j].Depth {
			return out[i].Depth < out[j].Depth
		}
		// What the neighbour IS comes before how specific it is: actors first,
		// then attributed entries, then those linked to nobody, then the ones
		// this checkout knows nothing about.
		ri, rj := neighbourRank(out[i]), neighbourRank(out[j])
		if ri != rj {
			return ri < rj
		}
		// Within attributed entries, fewer actors means more discriminating.
		if out[i].GroupCount != out[j].GroupCount {
			return out[i].GroupCount < out[j].GroupCount
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// PathHop is one step along a discovered path.
type PathHop struct {
	UUID       string `json:"uuid"`
	Tag        string `json:"tag,omitempty" jsonschema:"canonical MISP galaxy tag for this entry"`
	Value      string `json:"value,omitempty"`
	Galaxy     string `json:"galaxy,omitempty"`
	Via        string `json:"via,omitempty" jsonschema:"relation type taken to reach this node"`
	Confidence int    `json:"confidence,omitempty" jsonschema:"declarations backing the hop that reached this node"`
	Bridge     bool   `json:"bridge,omitempty" jsonschema:"this hop is the only link between the two sides; the path depends entirely on it"`
}

// ShortestPath finds a shortest route between two nodes using a bidirectional
// breadth-first search: it expands from both ends and stops when the frontiers
// meet. On a graph this dense that is the difference between milliseconds and
// seconds — expanding from one end alone explores a neighbourhood that grows
// roughly squared with depth.
//
// Returns nil when no path exists within maxDepth.
func (g *Graph) ShortestPath(fromUUID, toUUID string, maxDepth int, edgeTypes []string) []PathHop {
	from, okA := g.nodes[fromUUID]
	to, okB := g.nodes[toUUID]
	if !okA || !okB {
		return nil
	}
	if from == to {
		return []PathHop{{UUID: from.UUID, Tag: from.Tag(), Value: from.Value, Galaxy: from.Galaxy}}
	}
	if maxDepth <= 0 {
		maxDepth = 6
	}
	keep := edgeFilter(edgeTypes)

	// parent maps record how each node was reached, per side.
	fwd := map[*Node]link{from: {}}
	bwd := map[*Node]link{to: {}}
	fFront, bFront := []*Node{from}, []*Node{to}

	// expand advances one frontier and reports a meeting node if the other
	// side has already been there.
	expand := func(front []*Node, seen, other map[*Node]link) ([]*Node, *Node) {
		var next []*Node
		for _, n := range front {
			for _, e := range edgesOf(n, Both) {
				ok, via := e.matches(keep)
				if !ok {
					continue
				}
				if _, been := seen[e.To]; been {
					continue
				}
				seen[e.To] = link{prev: n, via: via, confidence: e.Confidence, bridge: e.Bridge}
				if _, met := other[e.To]; met {
					return next, e.To
				}
				next = append(next, e.To)
			}
		}
		return next, nil
	}

	for depth := 0; depth < maxDepth && len(fFront) > 0 && len(bFront) > 0; depth++ {
		var meet *Node
		// Always expand the smaller frontier: that is what keeps the search
		// cheap when one endpoint is a hub and the other is a leaf.
		if len(fFront) <= len(bFront) {
			fFront, meet = expand(fFront, fwd, bwd)
		} else {
			bFront, meet = expand(bFront, bwd, fwd)
		}
		if meet != nil {
			return stitch(meet, fwd, bwd)
		}
	}
	return nil
}

// link records how a node was reached during a bidirectional search.
type link struct {
	prev       *Node
	via        string
	confidence int
	bridge     bool
}

// stitch rebuilds the full route from the meeting node outward to both ends.
func stitch(meet *Node, fwd, bwd map[*Node]link) []PathHop {
	var head []PathHop
	for n := meet; n != nil; {
		l := fwd[n]
		head = append(head, PathHop{
			UUID: n.UUID, Tag: n.Tag(), Value: n.Value, Galaxy: n.Galaxy,
			Via: l.via, Confidence: l.confidence, Bridge: l.bridge,
		})
		n = l.prev
	}
	head = reverseHops(head)
	if len(head) > 0 {
		head[0].Via, head[0].Confidence, head[0].Bridge = "", 0, false
	}

	n := bwd[meet].prev
	for n != nil {
		l := bwd[n]
		head = append(head, PathHop{
			UUID: n.UUID, Tag: n.Tag(), Value: n.Value, Galaxy: n.Galaxy,
			Via: l.via, Confidence: l.confidence, Bridge: l.bridge,
		})
		n = l.prev
	}
	return head
}

func reverseHops(h []PathHop) []PathHop {
	for i, j := 0, len(h)-1; i < j; i, j = i+1, j-1 {
		h[i], h[j] = h[j], h[i]
	}
	return h
}

func edgesOf(n *Node, d Direction) []Edge {
	switch d {
	case Out:
		return n.Out
	case In:
		return n.In
	default:
		if len(n.In) == 0 {
			return n.Out
		}
		if len(n.Out) == 0 {
			return n.In
		}
		all := make([]Edge, 0, len(n.Out)+len(n.In))
		return append(append(all, n.Out...), n.In...)
	}
}

func edgeFilter(types []string) map[string]struct{} {
	if len(types) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(types))
	for _, t := range types {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			set[t] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// matches reports whether an edge passes a relation-type filter, and which
// type satisfied it.
//
// Every declared type is checked, not just the first: links are merged, so a
// relation declared used-by from one side and similar from the other carries
// both, and filtering on either must find it. Testing only Type would silently
// drop links the caller explicitly asked for.
func (e Edge) matches(keep map[string]struct{}) (bool, string) {
	if keep == nil {
		return true, e.Type
	}
	if _, ok := keep[strings.ToLower(e.Type)]; ok {
		return true, e.Type
	}
	for _, t := range e.Types {
		if _, ok := keep[strings.ToLower(t)]; ok {
			// Report the type that matched rather than the first declared: a
			// caller filtering on "similar" should see "similar" as the hop.
			return true, t
		}
	}
	return false, ""
}
