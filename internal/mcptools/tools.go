// Package mcptools is the MCP façade over the same service the REST API uses.
//
// Tool descriptions carry more weight here than in a REST API: they are the
// only thing a model reads before choosing. Three things are stated explicitly
// because getting them wrong produces confident misattribution — that
// gx_resolve returns ranked candidates rather than an answer, that a revoked
// entry is still returned rather than hidden, and that a high group_count
// means an entry distinguishes nobody.
package mcptools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sebdraven/mcp-misp-galaxy/internal/galaxy"
	"github.com/sebdraven/mcp-misp-galaxy/internal/service"
)

// Register wires the galaxy tools onto s.
func Register(s *mcp.Server, svc *service.Service) {
	r := &registry{svc: svc}

	mcp.AddTool(s, &mcp.Tool{
		Name: "gx_resolve",
		Description: "Resolve a threat actor, malware, tool or technique name against the MISP galaxy corpus. " +
			"Matches canonical names AND vendor synonyms, so any naming convention works as input. " +
			"Returns RANKED CANDIDATES, not a single answer: the same synonym often designates several clusters. " +
			"When 'ambiguous' is true, check the candidates before acting on the first one. " +
			"Each candidate carries a 'degree': relations in this corpus are concentrated in the MITRE galaxies, so a well-known malware " +
			"often resolves to several entries with very different degrees. To then call gx_neighbors or gx_path, pick the candidate with the highest degree, not the highest score. " +
			"Searches a threat-intelligence subset of the corpus by default \u2014 misp-galaxy also carries unrelated taxonomies " +
			"(firearms, culture collections, economic activity codes) that would otherwise pollute results. " +
			"The 'scope' field of the answer says what was actually searched. " +
			"Entries the corpus has deprecated are still returned, flagged 'revoked' and ranked last. " +
			"Every result carries a 'tag': the canonical MISP galaxy tag, which is what attaches to a MISP event — quote that rather than the uuid when the answer is going anywhere near MISP.",
	}, r.resolve)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "gx_node",
		Description: "Full detail for one galaxy entry by UUID: description, synonyms, decoded meta (country, refs, ATT&CK ids...) and a count of its relations by type. Use gx_resolve first to get the UUID.",
	}, r.node)

	mcp.AddTool(s, &mcp.Tool{
		Name: "gx_neighbors",
		Description: "Walk the relation graph outward from an entry. Relations cross galaxies, so this is how you go from a malware family to the actors using it and the techniques it implements. " +
			"It does NOT reach the reports documenting an entry — those live in metadata, outside the graph; use gx_refs for those. " +
			"IMPORTANT: relations in this corpus live almost entirely in the MITRE galaxies (mitre-malware, mitre-intrusion-set, mitre-attack-pattern). " +
			"The malpedia, threat-actor and tool galaxies carry far fewer, so always start from the candidate gx_resolve reported with the highest degree. Starting from a low-degree entry for the same thing returns almost nothing. " +
			"Traverses both directions by default, which is deliberate: relations are usually declared on one side only. " +
			"Unlike gx_resolve this is NOT limited to the server's CTI scope \u2014 a declared relation is meaningful whatever galaxy it lands in \u2014 so use 'galaxies' to narrow. Each result carries 'confidence' (declarations backing the hop) and 'bridge' (the hop is the sole join between two parts of the graph); a bridge at confidence 1 rests on one unverified claim and should be reported as provisional. Each result also carries 'group_count' — how many actors are linked to that entry. Results are ordered most-specific first, and anything flagged 'generic' is shared by so many actors that it distinguishes none of them; max_group_count strips those entirely.",
	}, r.neighbours)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "gx_path",
		Description: "Find a shortest relation path between two galaxy entries by UUID — e.g. what connects a given actor to a given malware family. Returns the chain of entries and the relation type taken at each hop. Each hop carries a 'confidence' (how many declarations back it) and a 'bridge' flag (it is the only link joining the two sides). When 'caveat' is present the route hangs on a single unverified assertion — report the connection as provisional, not as established. Both endpoints need relations to be connectable, so prefer the highest-degree UUID for each end: an empty path often means one endpoint has a degree of 0, not that the two are unrelated in reality.",
	}, r.path)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "gx_galaxies",
		Description: "List the galaxies in the loaded corpus with their entry counts. Useful to pick a value for the 'galaxy' filter on gx_resolve and gx_neighbors.",
	}, r.galaxies)

	mcp.AddTool(s, &mcp.Tool{
		Name: "gx_profile",
		Description: "Build the profile of an entry: everything linked to it, grouped by kind, with counts of what is specific, generic and unattributed. " +
			"This is the unit CTI attribution claims are made about — an actor's techniques and tooling, or a malware's actors and techniques — and grouping shows the shape a flat neighbour list hides. " +
			"Read the three counts before drawing anything from it: 'specific' entries are linked to exactly one actor and could serve as a signature; 'generic' ones are shared too widely to distinguish anybody; " +
			"'unattributed' ones have no actor at all, which is a gap in the corpus rather than exclusivity. A profile where specific is 0 supports no attribution, and the note says so.",
	}, r.profile)

	mcp.AddTool(s, &mcp.Tool{
		Name: "gx_refs",
		Description: "List the reference URLs recorded on a galaxy entry — mostly vendor reports analysing it, sometimes a catalogue record. " +
			"These are NOT reachable through gx_neighbors: they live in the entry's metadata, and although a 'references' galaxy exists nothing links to it, so no traversal ever finds one. Use this instead. " +
			"Also returns a per-publisher count — an entry described by one vendor is a single point of view, one described by several has been looked at independently. " +
			"Links back to the entry's own catalogue page are flagged 'self_referential' and sorted last; they are records rather than analyses, and are excluded from the publisher count.",
	}, r.refs)

	mcp.AddTool(s, &mcp.Tool{
		Name: "gx_generic",
		Description: "List the entries used by the most threat actors — the ones with the least attribution value. " +
			"Read this before drawing conclusions from a list of relations: a technique or tool shared by dozens of actors says nothing about who was behind an intrusion, " +
			"and treating it as evidence is a known route to misattribution. Pass a galaxy to scope it, e.g. mitre-attack-pattern for techniques or tool for shared tooling.",
	}, r.generic)

	mcp.AddTool(s, &mcp.Tool{
		Name: "gx_status",
		Description: "Report the loaded graph (entry and relation counts) and the state of the misp-galaxy checkout, including the commit it was built from. " +
			"Cite that commit when a result needs to be reproducible.",
	}, r.status)
}

type registry struct{ svc *service.Service }

// ---- inputs -----------------------------------------------------------------

type resolveInput struct {
	Name          string   `json:"name" jsonschema:"the name to resolve; any vendor naming convention, partial names and synonyms all work"`
	Galaxies      []string `json:"galaxies,omitempty" jsonschema:"restrict to these galaxy types, e.g. threat-actor, malpedia, mitre-attack-pattern, android, stalkerware. Omit to use the server's CTI scope; pass [\"all\"] to search the whole corpus including its non-threat taxonomies"`
	Limit         int      `json:"limit,omitempty" jsonschema:"max candidates (default 20)"`
	Group         bool     `json:"group,omitempty" jsonschema:"also return the candidates grouped by galaxy, which shows how many naming conventions cover this name"`
	Normalisation string   `json:"normalisation,omitempty" jsonschema:"how names are folded before matching. 'standard' (default) ignores case and punctuation, so APT28 and APT-28 match. 'aggressive' also strips MITRE id suffixes, platform prefixes, collective words like Group, and trailing vendor names — so win.icefog matches Icefog and 'LightSpy - S1185' matches LightSpy. Aggressive finds more and merges some entries that are not the same thing; run both and compare when it matters"`
}

type nodeInput struct {
	UUID string `json:"uuid" jsonschema:"galaxy entry UUID, as returned by gx_resolve"`
}

type neighboursInput struct {
	UUID          string   `json:"uuid" jsonschema:"starting entry UUID"`
	Depth         int      `json:"depth,omitempty" jsonschema:"hops to walk (default 1, capped at 4); 2 already spans malware to actor to technique"`
	Direction     string   `json:"direction,omitempty" jsonschema:"both (default), out or in"`
	Types         []string `json:"types,omitempty" jsonschema:"keep only these relation types, e.g. similar, used-by, subtechnique-of"`
	Galaxies      []string `json:"galaxies,omitempty" jsonschema:"keep only entries from these galaxy types, e.g. ['malpedia'] for malware families or ['threat-actor'] for the actors behind them"`
	MaxGroupCount int      `json:"max_group_count,omitempty" jsonschema:"keep only entries linked to AT MOST this many threat actors, and do not walk through the others. Inclusive: 5 keeps entries at 5 actors and drops those at 6. This boundary is not the same as the 'generic' flag, which is set from 10 actors upwards — pass 9 to remove everything flagged generic"`
	Limit         int      `json:"limit,omitempty" jsonschema:"max entries returned (default 200)"`
	WithPaths     bool     `json:"with_paths,omitempty" jsonschema:"include the route taken to reach each entry"`
	SkipDangling  bool     `json:"skip_dangling,omitempty" jsonschema:"drop entries referenced by a relation but not defined in this checkout"`
}

type profileInput struct {
	UUID  string `json:"uuid" jsonschema:"entry UUID, as returned by gx_resolve"`
	Depth int    `json:"depth,omitempty" jsonschema:"hops to include (default 1, capped at 4). 1 is what the entry itself is linked to; 2 reaches what those are linked to in turn"`
	Limit int    `json:"limit,omitempty" jsonschema:"max entries in the profile (default 500)"`
}

type genericInput struct {
	Galaxy string `json:"galaxy,omitempty" jsonschema:"restrict to one galaxy type, e.g. mitre-attack-pattern or tool; omit to look across the whole corpus"`
	Limit  int    `json:"limit,omitempty" jsonschema:"how many entries to return (default 10)"`
}

type pathInput struct {
	From     string   `json:"from" jsonschema:"origin entry UUID"`
	To       string   `json:"to" jsonschema:"destination entry UUID"`
	MaxDepth int      `json:"max_depth,omitempty" jsonschema:"give up beyond this many hops (default 6)"`
	Types    []string `json:"types,omitempty" jsonschema:"restrict the walk to these relation types"`
}

// ---- handlers ---------------------------------------------------------------

func (r *registry) resolve(ctx context.Context, _ *mcp.CallToolRequest, in resolveInput) (*mcp.CallToolResult, service.ResolveResult, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, service.ResolveResult{}, fmt.Errorf("name is required")
	}
	res, err := r.svc.Resolve(in.Name, in.Galaxies, in.Limit, in.Group, in.Normalisation)
	return nil, res, err
}

func (r *registry) node(ctx context.Context, _ *mcp.CallToolRequest, in nodeInput) (*mcp.CallToolResult, service.NodeDetail, error) {
	if strings.TrimSpace(in.UUID) == "" {
		return nil, service.NodeDetail{}, fmt.Errorf("uuid is required")
	}
	res, err := r.svc.Node(in.UUID)
	return nil, res, err
}

func (r *registry) neighbours(ctx context.Context, _ *mcp.CallToolRequest, in neighboursInput) (*mcp.CallToolResult, service.NeighboursResult, error) {
	if strings.TrimSpace(in.UUID) == "" {
		return nil, service.NeighboursResult{}, fmt.Errorf("uuid is required")
	}
	res, err := r.svc.Neighbours(in.UUID, galaxy.NeighbourOpts{
		Depth:         in.Depth,
		Direction:     galaxy.Direction(in.Direction),
		EdgeTypes:     in.Types,
		Galaxies:      in.Galaxies,
		MaxGroupCount: in.MaxGroupCount,
		Limit:         in.Limit,
		WithPaths:     in.WithPaths,
		SkipGhosts:    in.SkipDangling,
	})
	return nil, res, err
}

func (r *registry) profile(ctx context.Context, _ *mcp.CallToolRequest, in profileInput) (*mcp.CallToolResult, galaxy.Profile, error) {
	if strings.TrimSpace(in.UUID) == "" {
		return nil, galaxy.Profile{}, fmt.Errorf("uuid is required")
	}
	res, err := r.svc.Profile(in.UUID, in.Depth, in.Limit)
	return nil, res, err
}

func (r *registry) refs(ctx context.Context, _ *mcp.CallToolRequest, in nodeInput) (*mcp.CallToolResult, service.RefsResult, error) {
	if strings.TrimSpace(in.UUID) == "" {
		return nil, service.RefsResult{}, fmt.Errorf("uuid is required")
	}
	res, err := r.svc.Refs(in.UUID)
	return nil, res, err
}

func (r *registry) generic(ctx context.Context, _ *mcp.CallToolRequest, in genericInput) (*mcp.CallToolResult, service.GenericResult, error) {
	res, err := r.svc.MostGeneric(in.Galaxy, in.Limit)
	return nil, res, err
}

func (r *registry) path(ctx context.Context, _ *mcp.CallToolRequest, in pathInput) (*mcp.CallToolResult, service.PathResult, error) {
	if strings.TrimSpace(in.From) == "" || strings.TrimSpace(in.To) == "" {
		return nil, service.PathResult{}, fmt.Errorf("from and to are required")
	}
	res, err := r.svc.Path(in.From, in.To, in.MaxDepth, in.Types)
	return nil, res, err
}

// GalaxyList is the gx_galaxies output.
type GalaxyList struct {
	Count    int                 `json:"count"`
	Galaxies []galaxy.GalaxyInfo `json:"galaxies"`
}

func (r *registry) galaxies(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, GalaxyList, error) {
	gs, err := r.svc.Galaxies()
	if err != nil {
		return nil, GalaxyList{}, err
	}
	return nil, GalaxyList{Count: len(gs), Galaxies: gs}, nil
}

func (r *registry) status(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, service.StatusResult, error) {
	return nil, r.svc.Status(), nil
}
