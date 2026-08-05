// Package galaxy loads the MISP galaxy JSON corpus into an immutable in-memory
// graph and answers name-resolution and traversal queries against it.
//
// The graph is built once and never mutated, so reads need no locking. A
// reload builds a fresh graph alongside the live one and swaps it in
// atomically; in-flight readers keep walking the old graph until they are done
// and it is collected normally.
package galaxy

import "encoding/json"

// ---- on-disk shapes ---------------------------------------------------------
//
// Only the fields the graph needs are modelled. Everything else stays in Raw so
// a caller can ask for it without the loader having to know the shape of every
// galaxy's meta block — which varies a lot between galaxies.

// clusterFile is one file under clusters/.
type clusterFile struct {
	Name        string         `json:"name"`
	Type        string         `json:"type"`
	UUID        string         `json:"uuid"`
	Description string         `json:"description"`
	Category    string         `json:"category"`
	Source      string         `json:"source"`
	Version     int            `json:"version"`
	Values      []clusterValue `json:"values"`
}

// clusterValue is one entry in a cluster's values array — one node.
type clusterValue struct {
	UUID        string          `json:"uuid"`
	Value       string          `json:"value"`
	Description string          `json:"description"`
	Revoked     bool            `json:"revoked"`
	Meta        json.RawMessage `json:"meta"`
	Related     []relatedEntry  `json:"related"`
}

// relatedEntry is one declared edge. The dest-uuid key is hyphenated, so the
// tag is mandatory: field-name inference would never find it.
type relatedEntry struct {
	DestUUID string   `json:"dest-uuid"`
	Type     string   `json:"type"`
	Tags     []string `json:"tags,omitempty"`
}

// metaBlock is the only part of meta the index cares about. Decoded separately
// from Raw so the rest of meta stays untouched.
type metaBlock struct {
	Synonyms []string `json:"synonyms"`
}

// galaxyFile is one file under galaxies/ — the galaxy definition itself,
// carrying the human-readable name for a cluster type.
type galaxyFile struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	UUID        string `json:"uuid"`
	Description string `json:"description"`
	Namespace   string `json:"namespace"`
	Icon        string `json:"icon"`
}

// ---- graph shapes -----------------------------------------------------------

// Node is one cluster value. Pointers are stable for the lifetime of a Graph.
type Node struct {
	UUID        string
	Value       string
	Galaxy      string // the cluster's "type", e.g. threat-actor, mitre-attack-pattern
	Description string
	Synonyms    []string

	// Meta is the value's meta block, kept encoded. Decoding every meta map at
	// load time is the single biggest memory cost in this corpus and most nodes
	// are never looked at; callers decode the ones they need.
	Meta json.RawMessage

	// Dangling marks a node that only ever appeared as a related.dest-uuid,
	// never as a value of its own. Usually it means a galaxy is missing from
	// the checkout rather than that the data is broken — worth surfacing, not
	// worth dropping.
	Dangling bool

	// Revoked mirrors the corpus's own deprecation flag: merged or withdrawn
	// entries, common in the ATT&CK galaxies. Kept and demoted rather than
	// hidden — an older report may legitimately cite a revoked id, and finding
	// nothing would be worse than finding it flagged.
	Revoked bool

	Out []Edge
	In  []Edge
}

// Edge is one typed relation between two nodes.
type Edge struct {
	To   *Node
	Type string
}

// GalaxyInfo describes one galaxy and how many nodes it contributed.
type GalaxyInfo struct {
	Type        string `json:"type"`
	Name        string `json:"name,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	Description string `json:"description,omitempty"`
	Nodes       int    `json:"nodes"`
}

// Stats summarises a built graph.
type Stats struct {
	Nodes       int    `json:"nodes"`
	Edges       int    `json:"edges"`
	Dangling    int    `json:"dangling" jsonschema:"nodes referenced by an edge but never defined as a cluster value"`
	Revoked     int    `json:"revoked" jsonschema:"nodes the corpus marks as deprecated"`
	Galaxies    int    `json:"galaxies"`
	IndexedKeys int    `json:"indexed_keys" jsonschema:"distinct normalised names and synonyms in the resolver index"`
	SourceRef   string `json:"source_ref,omitempty" jsonschema:"commit of the misp-galaxy checkout the graph was built from"`
	LoadedAt    string `json:"loaded_at,omitempty"`
}
