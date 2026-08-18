// Package service is the single implementation both façades call. The HTTP and
// MCP layers do argument mapping and nothing else; every decision about
// defaults, caps and error shape lives here, so the two surfaces cannot drift
// apart.
package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
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

// ErrUnknownNormalisation is returned for a normalisation that is neither
// standard nor aggressive.
//
// Rejected rather than defaulted: a misspelt "agressive" silently answering
// under standard folding looks exactly like an aggressive resolve that found
// nothing extra, which is the one conclusion this parameter exists to test.
var ErrUnknownNormalisation = errors.New("unknown normalisation: want standard or aggressive")

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

// parseNormalisation maps the wire value to a mode. Empty means the default.
func parseNormalisation(s string) (galaxy.Normalisation, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(galaxy.Standard):
		return galaxy.Standard, nil
	case string(galaxy.Aggressive):
		return galaxy.Aggressive, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnknownNormalisation, s)
	}
}

// ResolveResult carries the ranked candidates for a name.
type ResolveResult struct {
	Query         string                  `json:"query"`
	Normalisation string                  `json:"normalisation" jsonschema:"which name-folding was used: standard or aggressive"`
	Scope         []string                `json:"scope,omitempty" jsonschema:"galaxies actually searched; absent means the whole corpus"`
	Count         int                     `json:"count"`
	Ambiguous     bool                    `json:"ambiguous" jsonschema:"more than one candidate matched; do not treat the first as the answer without checking"`
	Candidates    []galaxy.Candidate      `json:"candidates"`
	ByGalaxy      []galaxy.CandidateGroup `json:"by_galaxy,omitempty" jsonschema:"the same candidates grouped by galaxy, largest group first"`
}

// Resolve ranks the entries matching a name. galaxies overrides the service
// scope for this call; pass ScopeAll to search everything.
func (s *Service) Resolve(q string, galaxies []string, limit int, group bool, normalisation string) (ResolveResult, error) {
	g, err := s.graph()
	if err != nil {
		return ResolveResult{}, err
	}
	scope := s.scope
	if len(galaxies) > 0 {
		scope = normaliseScope(galaxies)
	}
	mode, err := parseNormalisation(normalisation)
	if err != nil {
		return ResolveResult{}, err
	}
	cands := g.ResolveWith(q, scope, limit, mode)
	res := ResolveResult{
		Query:         q,
		Normalisation: string(mode),
		Scope:         scope,
		Count:         len(cands),
		Ambiguous:     len(cands) > 1,
		Candidates:    cands,
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
	GroupCount  int            `json:"group_count" jsonschema:"how many distinct threat actors are linked to this entry. 1 means only one actor is known to use it; 0 means none is recorded, which is absence of data rather than exclusivity — and is normal for an actor entry, since actors are not counted against themselves"`
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
		GroupCount:  n.GroupCount,
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

	// WeakestLink names the least-supported hop on the route. A path is only
	// as good as its worst assertion, and a single-declaration bridge in the
	// middle means the whole connection rests on one unverified claim.
	WeakestLink string `json:"weakest_link,omitempty" jsonschema:"the hop the route depends on most, when one stands out as weak"`
	Caveat      string `json:"caveat,omitempty" jsonschema:"present when the route should not be read as established fact"`
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

	// Flag the weakest hop: a bridge backed by one declaration is exactly the
	// shape of the mis-links documented in the threat-actor naming literature,
	// where one wrong assertion fused two unrelated clusters.
	for i := 1; i < len(hops); i++ {
		if hops[i].Bridge && hops[i].Confidence <= 1 {
			res.WeakestLink = fmt.Sprintf("%s -> %s (%s)",
				hops[i-1].Value, hops[i].Value, hops[i].Via)
			res.Caveat = "this route depends on a single-declaration link that is the only join between the two sides; treat the connection as provisional"
			break
		}
	}
	return res, nil
}

// RefsResult lists the reference URLs recorded on an entry — vendor reports
// for the most part, plus any catalogue record, which is flagged and sorted
// last.
type RefsResult struct {
	UUID       string                    `json:"uuid"`
	Tag        string                    `json:"tag,omitempty"`
	Value      string                    `json:"value"`
	Galaxy     string                    `json:"galaxy"`
	Count      int                       `json:"count"`
	References []galaxy.Reference        `json:"references"`
	Publishers []galaxy.ReferenceSummary `json:"publishers,omitempty" jsonschema:"how many references each publisher contributed, catalogue records excluded; one publisher means a single point of view"`
	Note       string                    `json:"note,omitempty"`
}

// Refs returns the reference URLs recorded on an entry.
func (s *Service) Refs(uuid string) (RefsResult, error) {
	g, err := s.graph()
	if err != nil {
		return RefsResult{}, err
	}
	n, ok := g.Node(uuid)
	if !ok {
		return RefsResult{}, fmt.Errorf("%w: %s", ErrUnknownNode, uuid)
	}
	refs := n.References()
	res := RefsResult{
		UUID: n.UUID, Tag: n.Tag(), Value: n.Value, Galaxy: n.Galaxy,
		Count: len(refs), References: refs,
		Publishers: galaxy.ByPublisher(refs),
	}
	if len(refs) == 0 {
		// Worth stating: an empty list here is about this checkout, not about
		// whether anyone has written about the entry.
		res.Note = "no references recorded on this entry in this corpus; other galaxies may document the same thing"
	}
	return res, nil
}

// Profile returns what the corpus records about an entry, grouped by kind.
func (s *Service) Profile(uuid string, depth, limit int) (galaxy.Profile, error) {
	g, err := s.graph()
	if err != nil {
		return galaxy.Profile{}, err
	}
	p, ok := g.Profile(uuid, depth, limit)
	if !ok {
		return galaxy.Profile{}, fmt.Errorf("%w: %s", ErrUnknownNode, uuid)
	}
	return p, nil
}

// ErrInvalidRate is returned when a caller asks for a co-occurrence threshold
// outside [0,1], or one that is not a number at all.
var ErrInvalidRate = errors.New("min_rate must be a number between 0 and 1")

// ErrCompareOperands is returned when a comparison is missing one of its two
// entries.
var ErrCompareOperands = errors.New("comparison needs two uuids")

// ErrCompareSame is returned when both sides of a comparison are the same
// entry.
var ErrCompareSame = errors.New("cannot compare an entry with itself")

// ErrEmptyQuery is returned when a search is given nothing to look for.
var ErrEmptyQuery = errors.New("a query is required")

// ErrInvalidSimilarity is returned for a similarity threshold outside [0,1].
var ErrInvalidSimilarity = errors.New("min_similarity must be a number between 0 and 1")

// ErrCoOccurrenceScope is returned when neither an entry nor a galaxy is given
// to scope the search.
var ErrCoOccurrenceScope = errors.New("co-occurrence needs either a uuid or a galaxy to search")

// CoOccurrenceResult lists pairs used by nearly the same actors.
type CoOccurrenceResult struct {
	UUID      string                    `json:"uuid,omitempty"`
	Value     string                    `json:"value,omitempty"`
	Galaxy    string                    `json:"galaxy,omitempty"`
	MinRate   float64                   `json:"min_rate" jsonschema:"the threshold actually applied"`
	MinActors int                       `json:"min_actors" jsonschema:"entries linked to fewer actors than this were excluded, because the rate is meaningless over tiny sets"`
	Count     int                       `json:"count"`
	Pairs     []galaxy.CoOccurrencePair `json:"pairs"`
	Note      string                    `json:"note"`
}

// CoOccurrence finds pairs used by nearly the same actors, either within one
// entry's neighbourhood or across a whole galaxy.
//
// minRate is a pointer so that "omitted" and "0.0" stay distinguishable: 0 is a
// legitimate threshold meaning "show every overlap", and folding it into the
// default would make a documented value unreachable.
func (s *Service) CoOccurrence(uuid, galaxyType string, minRate *float64, minActors, limit int) (CoOccurrenceResult, error) {
	g, err := s.graph()
	if err != nil {
		return CoOccurrenceResult{}, err
	}
	// Trimmed here rather than at each façade: a query string of spaces would
	// otherwise pass the scope check and return an empty result as though the
	// galaxy simply held nothing.
	uuid = strings.TrimSpace(uuid)
	galaxyType = strings.TrimSpace(galaxyType)
	if uuid == "" && galaxyType == "" {
		return CoOccurrenceResult{}, ErrCoOccurrenceScope
	}

	var res CoOccurrenceResult
	if uuid != "" {
		n, ok := g.Node(uuid)
		if !ok {
			return CoOccurrenceResult{}, fmt.Errorf("%w: %s", ErrUnknownNode, uuid)
		}
		res.UUID, res.Value = n.UUID, n.Value
		// The UUID scope wins, so the galaxy is dropped rather than echoed:
		// reporting a scope that was not applied invites the answer to be read
		// as covering a whole taxonomy when it covers one neighbourhood.
		galaxyType = ""
	} else {
		res.Galaxy = galaxyType
	}

	rate := galaxy.CoOccurrenceThreshold
	if minRate != nil {
		// NaN has to be rejected explicitly: every comparison against it is
		// false, so it would slip past the rate filter and return every pair
		// while appearing to have applied a threshold.
		if math.IsNaN(*minRate) || *minRate < 0 || *minRate > 1 {
			return CoOccurrenceResult{}, fmt.Errorf("%w (got %v)", ErrInvalidRate, *minRate)
		}
		rate = *minRate
	}
	if minActors <= 0 {
		minActors = galaxy.MinCoOccurrenceActors
	}
	if limit <= 0 {
		limit = 20
	}

	pairs := g.CoOccurrence(galaxy.CoOccurrenceOpts{
		UUID: uuid, Galaxy: galaxyType,
		MinRate: rate, MinActors: minActors, Limit: limit,
	})
	res.MinRate, res.MinActors = rate, minActors
	res.Count, res.Pairs = len(pairs), pairs

	if len(pairs) > 0 {
		res.Note = "these pairs are used by nearly the same actors: they are one observation each, not two, and counting both inflates a profile without adding to it. The pairs that surface this way are usually semantically nested, so check whether one is simply a kind of the other"
	} else {
		res.Note = fmt.Sprintf("no pairs at or above this threshold among entries linked to at least %d actors; most of this corpus is documented for too few actors for the measure to say anything", minActors)
	}
	return res, nil
}

// Compare reports what two entries share and what distinguishes them.
func (s *Service) Compare(aUUID, bUUID string, opt galaxy.CompareOpts) (galaxy.Comparison, error) {
	g, err := s.graph()
	if err != nil {
		return galaxy.Comparison{}, err
	}
	aUUID, bUUID = strings.TrimSpace(aUUID), strings.TrimSpace(bUUID)
	if aUUID == "" || bUUID == "" {
		return galaxy.Comparison{}, ErrCompareOperands
	}
	if aUUID == bUUID {
		// Comparing an entry with itself yields a similarity of 1 that means
		// nothing; better to say so than to return a perfect score.
		return galaxy.Comparison{}, ErrCompareSame
	}
	for _, uuid := range []string{aUUID, bUUID} {
		if _, ok := g.Node(uuid); !ok {
			return galaxy.Comparison{}, fmt.Errorf("%w: %s", ErrUnknownNode, uuid)
		}
	}
	// Both nodes exist, so the graph can only succeed from here; the boolean is
	// discarded rather than handled twice.
	cmp, _ := g.Compare(aUUID, bUUID, opt)
	return cmp, nil
}

// FuzzyResult carries approximate name matches.
type FuzzyResult struct {
	Query         string              `json:"query"`
	MinSimilarity float64             `json:"min_similarity" jsonschema:"the threshold actually applied"`
	Scope         []string            `json:"scope,omitempty"`
	Count         int                 `json:"count"`
	Matches       []galaxy.FuzzyMatch `json:"matches"`
	Note          string              `json:"note"`
}

// Fuzzy finds entries whose names are close to a query without being equal.
func (s *Service) Fuzzy(q string, galaxies []string, minSimilarity *float64, limit int) (FuzzyResult, error) {
	g, err := s.graph()
	if err != nil {
		return FuzzyResult{}, err
	}
	q = strings.TrimSpace(q)
	if q == "" {
		return FuzzyResult{}, ErrEmptyQuery
	}

	threshold := galaxy.FuzzyThreshold
	if minSimilarity != nil {
		if math.IsNaN(*minSimilarity) || *minSimilarity < 0 || *minSimilarity > 1 {
			return FuzzyResult{}, fmt.Errorf("%w (got %v)", ErrInvalidSimilarity, *minSimilarity)
		}
		threshold = *minSimilarity
	}
	scope := s.scope
	if len(galaxies) > 0 {
		scope = normaliseScope(galaxies)
	}

	matches := g.FuzzyResolve(q, galaxy.FuzzyOpts{
		Galaxies: scope, MinSimilarity: threshold, Limit: limit,
	})
	res := FuzzyResult{
		Query: q, MinSimilarity: threshold, Scope: scope,
		Count: len(matches), Matches: matches,
	}

	blocked := 0
	for _, m := range matches {
		if m.Blocked {
			blocked++
		}
	}
	switch {
	case len(matches) == 0:
		res.Note = "no near names above the threshold; the entry may simply not be in this corpus"
	case blocked > 0:
		res.Note = "orthographic proximity is not identity. Some matches are flagged 'blocked': their own catalogue entries disagree on a discriminating attribute, so they are not the same thing however alike the names look. Read the signal breakdown before treating any of these as the same entry"
	default:
		res.Note = "orthographic proximity is not identity: APT28 and APT29 are one character apart and are different actors. Check the signal breakdown, and prefer a documented synonym over a close spelling"
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

// GenericResult lists the least discriminating entries of a galaxy.
type GenericResult struct {
	Galaxy  string                `json:"galaxy,omitempty"`
	Count   int                   `json:"count"`
	Entries []galaxy.GenericEntry `json:"entries"`
	Note    string                `json:"note"`
}

// MostGeneric returns the entries linked to the most threat actors.
func (s *Service) MostGeneric(galaxyType string, limit int) (GenericResult, error) {
	g, err := s.graph()
	if err != nil {
		return GenericResult{}, err
	}
	entries := g.MostGeneric(galaxyType, limit)
	return GenericResult{
		Galaxy:  galaxyType,
		Count:   len(entries),
		Entries: entries,
		Note:    "these entries are used by many actors; their presence in an intrusion does not point at any of them",
	}, nil
}

// StatusResult combines graph stats with the state of the data checkout.
type StatusResult struct {
	Loaded  bool         `json:"loaded"`
	Stats   galaxy.Stats `json:"stats"`
	Corpus  corpus.State `json:"corpus"`
	Warning string       `json:"warning,omitempty" jsonschema:"set when the corpus could not be synced but a usable one was already on disk; the commit reported is what actually answered"`
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
//
// A sync that fails while leaving usable data on disk is reported in the
// result rather than as an error: the caller asked to refresh, and telling
// them "it did not refresh, here is what you have" is more useful than an
// error that says nothing about the state they are left in.
func (s *Service) Sync() (StatusResult, error) {
	syncErr := error(nil)
	if _, err := s.mgr.Sync(); err != nil {
		if !errors.Is(err, corpus.ErrSyncFailed) {
			return StatusResult{}, err
		}
		syncErr = err
	}
	if _, err := s.Reload(); err != nil {
		return StatusResult{}, err
	}
	out := s.Status()
	if syncErr != nil {
		out.Warning = syncErr.Error()
	}
	return out, nil
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
