// Package service is the single implementation both façades call. The HTTP and
// MCP layers do argument mapping and nothing else; every decision about
// defaults, caps and error shape lives here, so the two surfaces cannot drift
// apart.
package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sebdraven/mcp-misp-galaxy/internal/corpus"
	"github.com/sebdraven/mcp-misp-galaxy/internal/galaxy"
)

// ErrNotLoaded is returned before the first successful corpus load.
var ErrNotLoaded = errors.New("galaxy corpus not loaded")

// ErrUnknownNode is returned for a UUID absent from the graph.
var ErrUnknownNode = errors.New("unknown uuid")

// DefaultScope is the set of galaxies searched when none is specified.
//
// It exists because misp-galaxy is no longer a threat-intelligence corpus: it
// has absorbed MISP taxonomies covering microbial culture collections,
// firearms, economic activity codes, drones and diseases, and those outweigh
// the CTI galaxies by volume. Resolving a name corpus-wide searches all of it.
//
// This list is a starting point, not doctrine — override it with WithScope.
var DefaultScope = []string{
	"malpedia",
	"threat-actor",
	"microsoft-activity-group",
	"360net-threat-actor",
	"intelligence-agency",
	"surveillance-vendor",
	"mitre-attack-pattern",
	"mitre-malware",
	"mitre-intrusion-set",
	"mitre-enterprise-attack-malware",
	"mitre-enterprise-attack-intrusion-set",
	"mitre-enterprise-attack-tool",
	"mitre-tool",
	"tool",
	"android",
	"stalkerware",
	"ransomware",
	"rat",
	"botnet",
	"banker",
	"backdoor",
	"stealer",
	"wiper",
	"exploit-kit",
	"cryptominers",
	"rmm-tool",
	"tds",
	"campaigns",
	"groups",
	"software",
	"technique",
}

// ScopeAll is the sentinel that disables scoping for one call or for the whole
// service.
const ScopeAll = "all"

// Service answers queries against whatever graph is currently live.
type Service struct {
	holder *galaxy.Holder
	mgr    *corpus.Manager
	root   string
	scope  []string
}

// Option configures a Service.
type Option func(*Service)

// WithScope sets the default galaxies searched by Resolve. A single entry
// equal to ScopeAll disables scoping.
func WithScope(galaxies []string) Option {
	return func(s *Service) { s.scope = normaliseScope(galaxies) }
}

// WithDataDir overrides where the corpus is read from. Without it the corpus
// is the submodule under the repository; with it, any directory holding
// clusters/ and galaxies/ will do — which is what a standalone binary needs,
// having no repository to sit in.
func WithDataDir(dir string) Option {
	return func(s *Service) {
		if dir != "" {
			s.root = dir
		}
	}
}

// New wires a service over a holder and the corpus manager backing reloads.
func New(h *galaxy.Holder, mgr *corpus.Manager, opts ...Option) *Service {
	s := &Service{holder: h, mgr: mgr, root: mgr.DataDir(), scope: DefaultScope}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Scope returns the default galaxy scope in effect.
func (s *Service) Scope() []string { return s.scope }

// normaliseScope resolves the ScopeAll sentinel to nil (no restriction).
func normaliseScope(in []string) []string {
	if len(in) == 1 && strings.EqualFold(strings.TrimSpace(in[0]), ScopeAll) {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, g := range in {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *Service) graph() (*galaxy.Graph, error) {
	g := s.holder.Get()
	if g == nil {
		return nil, ErrNotLoaded
	}
	return g, nil
}

// ---- queries ----------------------------------------------------------------

// ResolveResult carries the ranked candidates for a name.
type ResolveResult struct {
	Query      string                  `json:"query"`
	Scope      []string                `json:"scope,omitempty" jsonschema:"galaxies actually searched; absent means the whole corpus"`
	Count      int                     `json:"count"`
	Ambiguous  bool                    `json:"ambiguous" jsonschema:"more than one candidate matched; do not treat the first as the answer without checking"`
	Candidates []galaxy.Candidate      `json:"candidates"`
	ByGalaxy   []galaxy.CandidateGroup `json:"by_galaxy,omitempty" jsonschema:"the same candidates grouped by galaxy, largest group first"`
}

// Resolve ranks the entries matching a name. galaxies overrides the service
// scope for this call; pass ScopeAll to search everything.
func (s *Service) Resolve(q string, galaxies []string, limit int, group bool) (ResolveResult, error) {
	g, err := s.graph()
	if err != nil {
		return ResolveResult{}, err
	}
	scope := s.scope
	if len(galaxies) > 0 {
		scope = normaliseScope(galaxies)
	}
	cands := g.Resolve(q, scope, limit)
	res := ResolveResult{
		Query:      q,
		Scope:      scope,
		Count:      len(cands),
		Ambiguous:  len(cands) > 1,
		Candidates: cands,
	}
	if group {
		res.ByGalaxy = galaxy.GroupByGalaxy(cands)
	}
	return res, nil
}

// NodeDetail is one entry with its meta decoded and its immediate relations
// counted by type.
type NodeDetail struct {
	UUID        string         `json:"uuid"`
	Tag         string         `json:"tag,omitempty" jsonschema:"canonical MISP galaxy tag, e.g. misp-galaxy:threat-actor=\"APT28\" — this is what gets attached to a MISP event"`
	Value       string         `json:"value"`
	Galaxy      string         `json:"galaxy"`
	Description string         `json:"description,omitempty"`
	Synonyms    []string       `json:"synonyms,omitempty"`
	Revoked     bool           `json:"revoked,omitempty"`
	Synthetic   bool           `json:"synthetic,omitempty" jsonschema:"the corpus published this entry without a uuid; the uuid field is a locally derived key, not a MISP identifier"`
	Dangling    bool           `json:"dangling,omitempty"`
	Meta        map[string]any `json:"meta,omitempty"`
	RelationsBy map[string]int `json:"relations_by_type,omitempty" jsonschema:"count of adjacent relations per type, both directions"`
	Degree      int            `json:"degree"`
}

// Node returns one entry by UUID. This is where meta is finally decoded — the
// loader keeps it encoded precisely so this cost is paid per consulted node
// rather than across the whole corpus.
func (s *Service) Node(uuid string) (NodeDetail, error) {
	g, err := s.graph()
	if err != nil {
		return NodeDetail{}, err
	}
	n, ok := g.Node(uuid)
	if !ok {
		return NodeDetail{}, fmt.Errorf("%w: %s", ErrUnknownNode, uuid)
	}
	d := NodeDetail{
		UUID: n.UUID, Tag: n.Tag(), Value: n.Value, Galaxy: n.Galaxy,
		Description: n.Description, Synonyms: n.Synonyms,
		Revoked: n.Revoked, Synthetic: n.Synthetic, Dangling: n.Dangling,
		Degree:      len(n.Out) + len(n.In),
		RelationsBy: map[string]int{},
	}
	for _, e := range n.Out {
		d.RelationsBy[e.Type]++
	}
	for _, e := range n.In {
		d.RelationsBy[e.Type]++
	}
	if len(n.Meta) > 0 {
		var m map[string]any
		if json.Unmarshal(n.Meta, &m) == nil {
			d.Meta = m
		}
	}
	return d, nil
}

// NeighboursResult is a traversal outcome.
type NeighboursResult struct {
	Origin     string             `json:"origin"`
	Depth      int                `json:"depth"`
	Count      int                `json:"count"`
	Neighbours []galaxy.Neighbour `json:"neighbours"`
}

// Neighbours walks outward from a node.
func (s *Service) Neighbours(uuid string, opt galaxy.NeighbourOpts) (NeighboursResult, error) {
	g, err := s.graph()
	if err != nil {
		return NeighboursResult{}, err
	}
	if _, ok := g.Node(uuid); !ok {
		return NeighboursResult{}, fmt.Errorf("%w: %s", ErrUnknownNode, uuid)
	}
	ns := g.Neighbours(uuid, opt)
	depth := opt.Depth
	if depth <= 0 {
		depth = 1
	}
	return NeighboursResult{Origin: uuid, Depth: depth, Count: len(ns), Neighbours: ns}, nil
}

// PathResult is a route between two entries.
type PathResult struct {
	From  string           `json:"from"`
	To    string           `json:"to"`
	Found bool             `json:"found"`
	Hops  int              `json:"hops"`
	Path  []galaxy.PathHop `json:"path,omitempty"`
}

// Path finds a shortest route between two entries.
func (s *Service) Path(from, to string, maxDepth int, edgeTypes []string) (PathResult, error) {
	g, err := s.graph()
	if err != nil {
		return PathResult{}, err
	}
	if _, ok := g.Node(from); !ok {
		return PathResult{}, fmt.Errorf("%w: %s", ErrUnknownNode, from)
	}
	if _, ok := g.Node(to); !ok {
		return PathResult{}, fmt.Errorf("%w: %s", ErrUnknownNode, to)
	}
	hops := g.ShortestPath(from, to, maxDepth, edgeTypes)
	res := PathResult{From: from, To: to, Found: len(hops) > 0, Path: hops}
	if len(hops) > 0 {
		res.Hops = len(hops) - 1
	}
	return res, nil
}

// Galaxies lists the galaxies in the checkout.
func (s *Service) Galaxies() ([]galaxy.GalaxyInfo, error) {
	g, err := s.graph()
	if err != nil {
		return nil, err
	}
	return g.Galaxies(), nil
}

// StatusResult combines graph stats with the state of the data checkout.
type StatusResult struct {
	Loaded bool         `json:"loaded"`
	Stats  galaxy.Stats `json:"stats"`
	Corpus corpus.State `json:"corpus"`
}

// Status reports both halves: what is in memory, and what is on disk.
func (s *Service) Status() StatusResult {
	out := StatusResult{}
	if g := s.holder.Get(); g != nil {
		out.Loaded, out.Stats = true, g.Stats()
	}
	if st, err := s.mgr.Status(); err == nil {
		out.Corpus = st
	}
	return out
}

// ---- corpus lifecycle -------------------------------------------------------

// Reload rebuilds the graph from the current checkout and publishes it. The
// live graph is only replaced once the new one is fully built, so a failed
// reload leaves the running service untouched.
func (s *Service) Reload(opts ...galaxy.LoadOption) (galaxy.Stats, error) {
	g, err := galaxy.Load(s.root, s.corpusRef(), opts...)
	if err != nil {
		return galaxy.Stats{}, err
	}
	s.holder.Set(g)
	return g.Stats(), nil
}

// corpusRef establishes where the data came from, trying each deployment shape
// in turn. A result with no corpus reference cannot be replayed later, so this
// is worth more than one lookup.
func (s *Service) corpusRef() string {
	// Vendored as a submodule under a repository.
	if ref, err := s.mgr.Head(); err == nil && ref != "" {
		return ref
	}
	// Fetched standalone: the corpus directory is itself a clone.
	if ref := corpus.HeadOf(s.root); ref != "" {
		return ref
	}
	// Baked into a container image, where there is no git at all.
	return corpusRefFromBuild(s.root)
}

// corpusRefFromBuild recovers the corpus commit when no git repository backs
// the data. The image build writes the file inside the corpus directory; the
// environment variable overrides it, which is what a mounted volume needs
// since the file would then describe the wrong data.
func corpusRefFromBuild(dataDir string) string {
	if v := strings.TrimSpace(os.Getenv("GALAXY_CORPUS_REF")); v != "" {
		return v
	}
	raw, err := os.ReadFile(filepath.Join(dataDir, "CORPUS_REF"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// Sync brings the checkout back to the pinned commit, then reloads.
func (s *Service) Sync() (StatusResult, error) {
	if _, err := s.mgr.Sync(); err != nil {
		return StatusResult{}, err
	}
	if _, err := s.Reload(); err != nil {
		return StatusResult{}, err
	}
	return s.Status(), nil
}

// Advance moves the checkout to the remote tip, then reloads. Never called
// automatically: it changes what the corpus says, which has to be deliberate.
func (s *Service) Advance(branch string) (StatusResult, error) {
	if _, err := s.mgr.Advance(branch); err != nil {
		return StatusResult{}, err
	}
	if _, err := s.Reload(); err != nil {
		return StatusResult{}, err
	}
	return s.Status(), nil
}
