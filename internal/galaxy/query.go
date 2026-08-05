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
	UUID     string   `json:"uuid"`
	Value    string   `json:"value,omitempty"`
	Galaxy   string   `json:"galaxy,omitempty"`
	Depth    int      `json:"depth"`
	Via      string   `json:"via" jsonschema:"type of the relation on the last hop"`
	FromUUID string   `json:"from_uuid" jsonschema:"node this one was reached from"`
	Dangling bool     `json:"dangling,omitempty" jsonschema:"referenced by a relation but not defined in this checkout"`
	Path     []string `json:"path,omitempty" jsonschema:"uuids from the origin to this node, when requested"`
}

// NeighbourOpts tunes a traversal.
//
// Note that the service-level galaxy scope does NOT apply here, and that is
// deliberate: searching a name across unrelated taxonomies is noise, but
// following a relation someone declared is never noise — the arc exists
// because a human asserted it. Narrowing a traversal is done explicitly with
// Galaxies.
type NeighbourOpts struct {
	Depth      int       // hops, default 1
	Direction  Direction // default Both
	EdgeTypes  []string  // keep only these relation types; empty keeps all
	Galaxies   []string  // keep only entries from these galaxy types; empty keeps all
	Limit      int       // max nodes returned, default 200
	WithPaths  bool      // record the route to each node
	SkipGhosts bool      // drop dangling nodes from the result
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
			if !keep(e.Type) || visited[e.To] {
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
			n := Neighbour{
				UUID: e.To.UUID, Value: e.To.Value, Galaxy: e.To.Galaxy,
				Depth: cur.depth + 1, Via: e.Type,
				FromUUID: cur.node.UUID, Dangling: e.To.Dangling,
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
		return out[i].Value < out[j].Value
	})
	return out
}

// PathHop is one step along a discovered path.
type PathHop struct {
	UUID   string `json:"uuid"`
	Value  string `json:"value,omitempty"`
	Galaxy string `json:"galaxy,omitempty"`
	Via    string `json:"via,omitempty" jsonschema:"relation type taken to reach this node"`
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
		return []PathHop{{UUID: from.UUID, Value: from.Value, Galaxy: from.Galaxy}}
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
				if !keep(e.Type) {
					continue
				}
				if _, been := seen[e.To]; been {
					continue
				}
				seen[e.To] = link{prev: n, via: e.Type}
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
	prev *Node
	via  string
}

// stitch rebuilds the full route from the meeting node outward to both ends.
func stitch(meet *Node, fwd, bwd map[*Node]link) []PathHop {
	var head []PathHop
	for n := meet; n != nil; {
		l := fwd[n]
		head = append(head, PathHop{UUID: n.UUID, Value: n.Value, Galaxy: n.Galaxy, Via: l.via})
		n = l.prev
	}
	// head currently runs meet → from; reverse it.
	for i, j := 0, len(head)-1; i < j; i, j = i+1, j-1 {
		head[i], head[j] = head[j], head[i]
	}
	// The first hop has no incoming relation.
	if len(head) > 0 {
		head[0].Via = ""
	}

	n := bwd[meet].prev
	for n != nil {
		l := bwd[n]
		head = append(head, PathHop{UUID: n.UUID, Value: n.Value, Galaxy: n.Galaxy, Via: bwd[n].via})
		n = l.prev
	}
	return head
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

func edgeFilter(types []string) func(string) bool {
	if len(types) == 0 {
		return func(string) bool { return true }
	}
	set := make(map[string]struct{}, len(types))
	for _, t := range types {
		set[strings.ToLower(strings.TrimSpace(t))] = struct{}{}
	}
	return func(t string) bool {
		_, ok := set[strings.ToLower(t)]
		return ok
	}
}
