# mcp-misp-galaxy

Loads the [MISP galaxy](https://github.com/MISP/misp-galaxy) corpus into an
in-memory graph and serves it three ways: an MCP server, a REST API, and a
terminal UI.

The corpus ships as a git submodule, so nothing here talks to a MISP instance
and nothing needs an API key or network access at query time. Roughly 55,000
entries and 59,000 relations, loaded in about a third of a second.

**Not to be confused with [`misp-galaxy-mcp`](https://github.com/MISP/misp-galaxy-mcp)**,
MISP's own Python MCP server. Two characters apart, two different projects.
That one does keyword search and returns canonical MISP tags; this one adds the
relation graph the corpus declares between clusters.

---

## Why a graph

Every cluster value carries a `related` array of `dest-uuid` plus a relation
type, and those edges cross galaxies. That is what makes them worth loading: a
malware family reaches the threat actors using it, an actor reaches the
techniques it implements, and none of that is recoverable by keyword search.

Three properties of the data shape the whole design.

### Relations are concentrated in the MITRE galaxies

This is the single most useful thing to know before using the traversal tools.
`mitre-malware`, `mitre-intrusion-set` and `mitre-attack-pattern` are densely
linked; `malpedia`, `threat-actor` and `tool` carry only a handful of relations
each, and `references` has none pointing at it at all.

The consequence is concrete. ShadowPad resolves to three entries:

| Galaxy | Score | Degree |
|---|---|---|
| `tool` | 100 | 3 |
| `malpedia` | 100 | 1 |
| `mitre-malware` | 90 | **28** |

The best-scoring candidate is not the useful one. So `resolve` reports a
`degree` per candidate — pick the one with edges, not the one at the top.

### Relations are usually declared on one side only

Traversal follows both directions by default. Following outgoing edges alone
silently hides half the neighbourhood.

### Many `dest-uuid` values point nowhere

About 1% of edges target a value no cluster file defines. Those become
*dangling* nodes rather than being dropped: an unresolved destination usually
means a galaxy is missing from the checkout, which is worth seeing rather than
silently discarding.

---

## Install

```
git clone --recurse-submodules https://github.com/sebdraven/mcp-misp-galaxy
go build -o bin/mcp-misp-galaxy ./cmd/mcp-misp-galaxy
go build -o bin/galaxy-tui ./cmd/galaxy-tui
```

Cloned without `--recurse-submodules`? The binaries initialise the submodule
themselves on first run — that first clone pulls the full corpus history and
takes a while.

Keep the binaries inside the repository. The corpus is a submodule, so the
process needs `-root` pointing at the checkout; installing to `~/go/bin` and
losing track of `-root` is the easiest way to get a server that dies at startup.

## Quick check

```
bin/mcp-misp-galaxy -stats          # counters and checkout state
bin/mcp-misp-galaxy -galaxies       # inventory, by size
bin/mcp-misp-galaxy -resolve APT28  # ranked candidates as JSON
```

---

## The galaxy scope

`misp-galaxy` is no longer a threat-intelligence corpus. Its two largest
galaxies are microbial culture collections and firearms; it also carries
economic activity codes, drones and diseases. Together those outweigh
`malpedia`, `threat-actor`, `tool`, `mitre-malware` and `mitre-attack-pattern`
combined.

So name resolution runs against a CTI subset by default (`DefaultScope` in
`internal/service`). Override it per process:

```
bin/mcp-misp-galaxy -scope malpedia,android,stalkerware -resolve Cocospy
bin/mcp-misp-galaxy -scope all -resolve Anthrax
```

or per request, with the `galaxies` argument.

**The scope applies to search only, never to traversal.** Searching a name
across unrelated taxonomies is noise; following a relation someone declared is
not — the edge exists because a human asserted it. A galaxy named in the scope
but absent from the checkout is reported at startup, since it would otherwise
fail silently as "no results".

## Resolution returns candidates, not an answer

The same synonym regularly designates several clusters across several galaxies.
`APT28` matches seven, because seven vendors have their own name for it, and
that spread is itself information — it is the map of naming conventions.
Collapsing it to one answer produces silent misattribution.

Results come back ranked, with the reason for each match (`value`, `synonym`,
`value_prefix`, `synonym_prefix`, `substring`), a `degree`, and an `ambiguous`
flag. Pass `group` to get them bucketed by galaxy.

Every result also carries its canonical MISP tag —
`misp-galaxy:threat-actor="APT28"` — which is what attaches to a MISP event. A
UUID identifies the entry but attaches to nothing, so quote the tag whenever
the answer is heading anywhere near MISP.

Entries the corpus marks `revoked` are still returned, flagged and ranked below
every live entry: an older report may legitimately cite a revoked identifier,
and finding nothing is worse than finding it flagged.

---

## Transports

```
bin/mcp-misp-galaxy                    # MCP over stdio (default)
bin/mcp-misp-galaxy -transport http    # MCP over streamable HTTP
bin/mcp-misp-galaxy -transport rest    # REST API
```

### MCP tools

| Tool | |
|---|---|
| `gx_resolve` | name → ranked candidates, with degree |
| `gx_node` | one entry, meta decoded, relations counted by type |
| `gx_neighbors` | walk outward, filtered by relation type and galaxy |
| `gx_path` | shortest relation path between two entries |
| `gx_galaxies` | inventory with entry counts |
| `gx_status` | graph counters and corpus checkout state |

### Claude Desktop

```json
"misp-galaxy": {
  "command": "/path/to/mcp-misp-galaxy/bin/mcp-misp-galaxy",
  "args": ["-root", "/path/to/mcp-misp-galaxy"],
  "env": { "GALAXY_SCOPE": "malpedia,threat-actor,mitre-malware,android" }
}
```

`-root` is not optional: the default is `"."`, and the working directory of a
process launched by the app is not the repository.

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

---

## Terminal UI

```
bin/galaxy-tui
```

A separate binary: the TUI pulls in bubbletea, bubbles and lipgloss, and none
of that belongs in a container image whose job is to answer MCP calls. Strictly
read-only — no key binding moves the corpus checkout.

Navigation is a stack, not a set of screens, because that is how an attribution
is actually explored: descend from a family to an actor to its techniques, lose
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
bin/galaxy-tui -marks json > trail.json
```

Loading messages go to stderr, so redirection stays clean.

---

## Corpus state

The submodule pins a commit, which is what makes a result reproducible: a name
resolution that shifts between two runs is worthless in an investigation.

`Sync` restores the pinned commit and runs at every start. `Advance` moves to
the remote tip and is never automatic — it leaves the parent repository's
submodule pointer dirty, because bumping the corpus belongs in a commit.

The commit appears in the load log, in the TUI header, in `/status`, and in the
exported trail.

---

## Known gaps

**References are not in the graph.** They live in each entry's `meta.refs`. The
`references` galaxy exists and holds 5,000+ entries, but nothing links to it, so
there is no walking from an entry to the reports documenting it. A dedicated
accessor would serve better than traversal.

**No producer filter.** The corpus records `meta.name-attribution` as
`<name>:<producer UUID>`, which answers "who calls it what" more precisely than
grouping by galaxy does.

**Scope is fixed per process in the TUI.** An empty result is therefore
ambiguous: the name may not exist, or it may live outside the scope.

## Licence

MIT
