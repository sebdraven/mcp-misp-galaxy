# mcp-misp-galaxy

Loads the [MISP galaxy](https://github.com/MISP/misp-galaxy) corpus into an
in-memory graph and serves it three ways: an MCP server, a REST API, and a
terminal UI.

The corpus ships as a git submodule, so nothing here talks to a MISP instance
and nothing needs an API key or network access at query time.

**Not to be confused with [`misp-galaxy-mcp`](https://github.com/MISP/misp-galaxy-mcp)**,
MISP's own Python MCP server. Two characters apart, two different projects.
That one does keyword search and returns canonical MISP tags; this one adds the
relation graph the corpus declares between clusters.

## Why a graph

Every cluster value carries a `related` array of `dest-uuid` plus a relation
type, and those edges cross galaxies. That is what makes them worth loading: a
malware family reaches the threat actors using it, an actor reaches the
techniques it implements, and none of that is recoverable by keyword search.

**Where the relations actually are.** They are concentrated almost entirely in
the MITRE galaxies. `malpedia`, `threat-actor`, `tool` and `references` are
largely relation-free, so a well-known malware can resolve to three entries of
which only the MITRE one is traversable at all. `resolve` reports a `degree`
per candidate for exactly this reason: pick the one with edges, not the
highest-scoring one.

Two further properties of the data shape the design:

**Relations are usually declared on one side only.** Traversal follows both
directions by default; following outgoing edges alone silently hides half the
neighbourhood.

**A `dest-uuid` often points at a value no cluster file defines.** Those
targets become *dangling* nodes rather than being dropped — an unresolved
destination usually means a galaxy is missing from the checkout, which is worth
seeing.

## Install

```
git clone --recurse-submodules https://github.com/sebdraven/mcp-misp-galaxy
go build ./...
```

If you cloned without `--recurse-submodules`, the binaries will initialise the
submodule themselves on first run — that first clone pulls the full corpus
history and takes a while.

## Quick check

```
go run ./cmd/mcp-misp-galaxy -stats
go run ./cmd/mcp-misp-galaxy -galaxies
go run ./cmd/mcp-misp-galaxy -resolve APT28
```

Roughly 55,000 entries and 59,000 relations, built in about a third of a
second.

## The galaxy scope

`misp-galaxy` is no longer a threat-intelligence corpus. Its two largest
galaxies are microbial culture collections and firearms; it also carries
economic activity codes, drones and diseases. Together those outweigh
`malpedia`, `threat-actor`, `tool`, `mitre-malware` and `mitre-attack-pattern`
combined.

So name resolution runs against a CTI subset by default (see `DefaultScope` in
`internal/service`). Override it:

```
go run ./cmd/mcp-misp-galaxy -scope malpedia,android,stalkerware -resolve Cocospy
go run ./cmd/mcp-misp-galaxy -scope all -resolve Anthrax
```

The scope applies to **search only**, never to traversal. Searching a name
across unrelated taxonomies is noise; following a relation someone declared is
not — the edge exists because a human asserted it.

## Resolution returns candidates, not an answer

The same synonym regularly designates several clusters across several galaxies.
`APT28` matches seven, because seven vendors have their own name for it, and
that spread is itself information. Collapsing it to one answer produces silent
misattribution, so results come back ranked with the reason for each match
(`value`, `synonym`, `value_prefix`, `synonym_prefix`, `substring`) and an
`ambiguous` flag.

Entries the corpus marks `revoked` are still returned, flagged and ranked below
every live entry. An older report may legitimately cite a revoked identifier,
and finding nothing is worse than finding it flagged.

## Transports

```
go run ./cmd/mcp-misp-galaxy                    # MCP over stdio (default)
go run ./cmd/mcp-misp-galaxy -transport http    # MCP over streamable HTTP
go run ./cmd/mcp-misp-galaxy -transport rest    # REST API
```

### MCP tools

| Tool | |
|---|---|
| `gx_resolve` | name → ranked candidates |
| `gx_node` | one entry, with meta decoded and relations counted by type |
| `gx_neighbors` | walk outward, filtered by relation type and galaxy |
| `gx_path` | shortest relation path between two entries |
| `gx_galaxies` | inventory with entry counts |
| `gx_status` | graph counters and corpus checkout state |

### REST

```
GET  /resolve?q=&galaxy=&limit=&group=
GET  /node/{uuid}
GET  /neighbors/{uuid}?depth=&direction=&type=&galaxy=&limit=&paths=
GET  /path?from=&to=&max_depth=&type=
GET  /galaxies
GET  /status
POST /admin/sync      bring the checkout back to the pinned commit
POST /admin/advance   move to the remote tip (never automatic)
POST /admin/reload    rebuild the graph from what is on disk
```

`/neighbors` takes two filters that work differently. `type` restricts what is
**traversed** — an excluded edge is not followed, so whatever lies behind it
becomes unreachable. `galaxy` restricts what is **reported** — an entry outside
the filter can still bridge to one inside it, so it is walked through but not
returned.

## Terminal UI

```
go run ./cmd/galaxy-tui
```

A separate binary: the TUI pulls in bubbletea, bubbles and lipgloss, and none
of that belongs in a container image whose job is to answer MCP calls.

Navigation is a stack, not a set of screens, because that is how an attribution
is actually explored — descend from a family to an actor to its reports, lose
the thread, step back one level.

| | |
|---|---|
| `↑↓` `jk` | move |
| `enter` | descend into an entry |
| `←` `esc` | back one level |
| `space` | mark |
| `f` `F` | cycle the galaxy filter on the current entry's relations |
| `m` | show marked |
| `/` | new search |
| `q` | quit |

Marked entries are printed to stdout on exit, with the corpus commit:

```
go run ./cmd/galaxy-tui -marks json > trail.json
```

Loading messages go to stderr so that redirection stays clean.

## Corpus state

The submodule pins a commit, which is what makes a result reproducible: a name
resolution that shifts between two runs is worthless in an investigation.

`Sync` restores the pinned commit and runs at every start. `Advance` moves to
the remote tip and is never automatic — it leaves the parent repository's
submodule pointer dirty, because bumping the corpus belongs in a commit.

The commit appears in the load log, in the TUI header, in `/status`, and in the
exported trail.

## Known gaps

No tests. The Python sibling has 73; this has none, and the two-pass loader and
the bidirectional path search are exactly the kind of code a refactor breaks
quietly.

Results carry UUIDs, not canonical MISP tags (`misp-galaxy:threat-actor="APT28"`).
In a MISP workflow the tag is what gets attached to an event; a UUID attaches to
nothing.

References live in each entry's `meta.refs`, not in the graph. The `references`
galaxy exists and is large, but nothing links to it, so there is no way to walk
from an entry to the reports documenting it — a dedicated accessor would serve
better than traversal.

No producer filter. The corpus records `meta.name-attribution` as
`<name>:<producer UUID>`, which answers "who calls it what" more precisely than
grouping by galaxy does.

The TUI cannot widen the scope to `all` without a restart, so an empty result
is ambiguous: the name may not exist, or it may live outside the scope.

## Licence

MIT
