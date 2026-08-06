package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/sebdraven/mcp-misp-galaxy/internal/galaxy"
	"github.com/sebdraven/mcp-misp-galaxy/internal/service"
)

// The navigation model is a stack, not a set of screens. Exploring an
// attribution means descending — actor, then its tools, then the techniques
// those implement — losing the thread, and stepping back one level. A stack is
// that movement; a tabbed layout is not.

type rowKind int

const (
	rowHeader rowKind = iota
	rowEntry
)

// row is one printable line. Headers are galaxy names in the results view and
// relation types in the node view.
type row struct {
	kind     rowKind
	label    string
	uuid     string
	galaxy   string
	note     string // match reason, or relation type
	revoked  bool
	dangling bool
}

func (r row) selectable() bool { return r.kind == rowEntry && r.uuid != "" }

// frame is one level of the navigation stack.
type frame struct {
	title  string
	rows   []row
	cursor int
	offset int
	detail *service.NodeDetail // nil for a results frame

	// Neighbour frames keep the unfiltered list so the galaxy filter is a
	// local toggle rather than a round trip: an actor with 200 relations is
	// exactly when you want to flip between "its reports" and "its malware"
	// without losing your place.
	allNeighbours []galaxy.Neighbour
	galaxyFilter  string
	galaxyOrder   []string
}

// mark is a noted entry, kept in visit order so the exported trail reads as
// the path actually walked.
type mark struct {
	UUID   string `json:"uuid"`
	Value  string `json:"value"`
	Galaxy string `json:"galaxy"`
}

type model struct {
	svc       *service.Service
	scope     []string
	sourceRef string
	version   string

	input     textinput.Model
	searching bool

	stack []*frame

	marks  []mark
	marked map[string]bool

	width, height int
	status        string
	err           string
	quitting      bool
}

func newModel(svc *service.Service, version string) model {
	ti := textinput.New()
	ti.Placeholder = "actor, malware or technique name"
	ti.Prompt = "search: "
	ti.CharLimit = 120
	ti.Focus()

	return model{
		svc:       svc,
		scope:     svc.Scope(),
		sourceRef: svc.Status().Stats.SourceRef,
		version:   version,
		input:     ti,
		searching: true,
		marked:    map[string]bool{},
		status:    "type a name and press enter",
	}
}

func (m model) Init() tea.Cmd { return textinput.Blink }

// ---- update -----------------------------------------------------------------

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			m.quitting = true
			return m, tea.Quit
		}
		if m.searching {
			return m.updateSearch(msg)
		}
		return m.updateBrowse(msg)
	}
	return m, nil
}

func (m model) updateSearch(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		q := strings.TrimSpace(m.input.Value())
		if q == "" {
			return m, nil
		}
		m.searching = false
		return m.runSearch(q), nil
	case tea.KeyEsc:
		// Only leave the search box if there is something to go back to.
		if len(m.stack) > 0 {
			m.searching = false
			m.input.Blur()
		}
		return m, nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m model) updateBrowse(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	f := m.top()
	if f == nil {
		m.searching = true
		m.input.Focus()
		return m, nil
	}

	switch msg.String() {
	case "q":
		m.quitting = true
		return m, tea.Quit

	case "/":
		m.searching = true
		m.input.SetValue("")
		m.input.Focus()
		m.status = "type a name and press enter"
		return m, nil

	case "up", "k":
		m.moveCursor(-1)
	case "down", "j":
		m.moveCursor(1)
	case "pgup":
		m.moveCursor(-10)
	case "pgdown":
		m.moveCursor(10)
	case "home", "g":
		f.cursor = 0
		m.snapToSelectable(1)
	case "end", "G":
		f.cursor = len(f.rows) - 1
		m.snapToSelectable(-1)

	case "enter", "l", "right":
		if r, ok := m.current(); ok {
			return m.openNode(r.uuid), nil
		}

	case "esc", "backspace", "h", "left":
		if len(m.stack) > 1 {
			m.stack = m.stack[:len(m.stack)-1]
			m.err = ""
			m.status = ""
		} else {
			m.searching = true
			m.input.Focus()
		}

	case " ":
		if r, ok := m.current(); ok {
			m.toggleMark(r)
		}

	case "m":
		return m.showMarks(), nil

	case "f":
		m.cycleGalaxyFilter(1)
	case "F":
		m.cycleGalaxyFilter(-1)
	}
	return m, nil
}

// cycleGalaxyFilter steps through the galaxies present among the current
// node's neighbours, plus an "all" position.
func (m *model) cycleGalaxyFilter(dir int) {
	f := m.top()
	if f == nil || f.detail == nil || len(f.galaxyOrder) == 0 {
		return
	}
	options := append([]string{""}, f.galaxyOrder...)
	idx := 0
	for i, o := range options {
		if o == f.galaxyFilter {
			idx = i
			break
		}
	}
	idx = (idx + dir + len(options)) % len(options)
	f.galaxyFilter = options[idx]
	m.rebuildNeighbourRows(f)
	m.cursorToFirstSelectable()
	if f.galaxyFilter == "" {
		m.status = fmt.Sprintf("%d relations, all galaxies", len(f.allNeighbours))
	} else {
		m.status = fmt.Sprintf("filtered to %s", f.galaxyFilter)
	}
}

// ---- actions ----------------------------------------------------------------

func (m model) runSearch(q string) model {
	res, err := m.svc.Resolve(q, nil, 100, true)
	if err != nil {
		m.err = err.Error()
		return m
	}
	m.err = ""

	f := &frame{title: fmt.Sprintf("results for %q", q)}
	if res.Count == 0 {
		// Silence here is ambiguous: the name may not exist, or it may live in
		// a galaxy outside the scope. Say which is being searched.
		f.rows = append(f.rows, row{kind: rowHeader,
			label: fmt.Sprintf("nothing in scope (%d galaxies) — press / and try another name", len(m.scope))})
	}
	for _, g := range res.ByGalaxy {
		f.rows = append(f.rows, row{kind: rowHeader,
			label: fmt.Sprintf("%s (%d)", g.Galaxy, g.Count)})
		for _, c := range g.Candidates {
			f.rows = append(f.rows, row{
				kind: rowEntry, label: c.Value, uuid: c.UUID,
				galaxy: c.Galaxy, note: c.Reason, revoked: c.Revoked,
			})
		}
	}
	m.stack = []*frame{f} // a new search resets the trail
	m.cursorToFirstSelectable()
	m.status = fmt.Sprintf("%d candidates across %d galaxies", res.Count, len(res.ByGalaxy))
	if res.Ambiguous {
		m.status += " — ambiguous, check before concluding"
	}
	return m
}

func (m model) openNode(uuid string) model {
	detail, err := m.svc.Node(uuid)
	if err != nil {
		m.err = err.Error()
		return m
	}
	// Fetched unfiltered on purpose — the galaxy filter below is applied
	// locally, so toggling it costs nothing.
	nres, err := m.svc.Neighbours(uuid, galaxy.NeighbourOpts{
		Depth: 1, Direction: galaxy.Both, Limit: 1000,
	})
	if err != nil {
		m.err = err.Error()
		return m
	}
	m.err = ""

	f := &frame{title: detail.Value, detail: &detail, allNeighbours: nres.Neighbours}

	seen := map[string]bool{}
	for _, n := range nres.Neighbours {
		if n.Galaxy != "" && !seen[n.Galaxy] {
			seen[n.Galaxy] = true
			f.galaxyOrder = append(f.galaxyOrder, n.Galaxy)
		}
	}
	sortStrings(f.galaxyOrder)
	m.rebuildNeighbourRows(f)

	m.stack = append(m.stack, f)
	m.cursorToFirstSelectable()
	m.status = fmt.Sprintf("%d relations across %d galaxies", nres.Count, len(f.galaxyOrder))
	return m
}

// rebuildNeighbourRows regroups the frame's neighbours by relation type,
// honouring the current galaxy filter. Grouping by relation type rather than
// listing flat because "what is linked to this, and how" is the question being
// asked: a used-by and a similar do not carry the same weight.
func (m *model) rebuildNeighbourRows(f *frame) {
	f.rows = nil

	byType := map[string][]galaxy.Neighbour{}
	var order []string
	kept := 0
	for _, n := range f.allNeighbours {
		if f.galaxyFilter != "" && n.Galaxy != f.galaxyFilter {
			continue
		}
		kept++
		if _, seen := byType[n.Via]; !seen {
			order = append(order, n.Via)
		}
		byType[n.Via] = append(byType[n.Via], n)
	}
	sortStrings(order)

	for _, via := range order {
		ns := byType[via]
		label := via
		if label == "" {
			label = "(untyped)"
		}
		f.rows = append(f.rows, row{kind: rowHeader,
			label: fmt.Sprintf("%s (%d)", label, len(ns))})
		for _, n := range ns {
			value := n.Value
			if n.Dangling {
				value = n.UUID + "  [not in this checkout]"
			}
			f.rows = append(f.rows, row{
				kind: rowEntry, label: value, uuid: n.UUID,
				galaxy: n.Galaxy, note: n.Via, dangling: n.Dangling,
			})
		}
	}
	if kept == 0 {
		msg := "no relations"
		if f.galaxyFilter != "" {
			msg = "no relations in " + f.galaxyFilter + " — press f to widen"
		}
		f.rows = append(f.rows, row{kind: rowHeader, label: msg})
	}
}

func (m model) showMarks() model {
	f := &frame{title: fmt.Sprintf("marked (%d)", len(m.marks))}
	if len(m.marks) == 0 {
		f.rows = append(f.rows, row{kind: rowHeader, label: "nothing marked — press space on an entry"})
	}
	for _, mk := range m.marks {
		f.rows = append(f.rows, row{
			kind: rowEntry, label: mk.Value, uuid: mk.UUID, galaxy: mk.Galaxy,
		})
	}
	m.stack = append(m.stack, f)
	m.cursorToFirstSelectable()
	m.status = "marked entries are printed on exit"
	return m
}

func (m *model) toggleMark(r row) {
	if m.marked[r.uuid] {
		delete(m.marked, r.uuid)
		for i, mk := range m.marks {
			if mk.UUID == r.uuid {
				m.marks = append(m.marks[:i], m.marks[i+1:]...)
				break
			}
		}
		m.status = "unmarked " + r.label
		return
	}
	m.marked[r.uuid] = true
	m.marks = append(m.marks, mark{UUID: r.uuid, Value: r.label, Galaxy: r.galaxy})
	m.status = fmt.Sprintf("marked %s (%d total)", r.label, len(m.marks))
}

// ---- cursor -----------------------------------------------------------------

func (m *model) top() *frame {
	if len(m.stack) == 0 {
		return nil
	}
	return m.stack[len(m.stack)-1]
}

func (m *model) current() (row, bool) {
	f := m.top()
	if f == nil || f.cursor < 0 || f.cursor >= len(f.rows) {
		return row{}, false
	}
	r := f.rows[f.cursor]
	return r, r.selectable()
}

// moveCursor steps by delta and then keeps going in the same direction until it
// lands on a selectable row, so headers are skipped rather than sat on.
func (m *model) moveCursor(delta int) {
	f := m.top()
	if f == nil || len(f.rows) == 0 {
		return
	}
	step := 1
	if delta < 0 {
		step = -1
	}
	target := f.cursor + delta
	for target >= 0 && target < len(f.rows) && !f.rows[target].selectable() {
		target += step
	}
	if target < 0 || target >= len(f.rows) {
		return
	}
	f.cursor = target
}

func (m *model) snapToSelectable(dir int) {
	f := m.top()
	if f == nil {
		return
	}
	for f.cursor >= 0 && f.cursor < len(f.rows) && !f.rows[f.cursor].selectable() {
		f.cursor += dir
	}
	if f.cursor < 0 {
		f.cursor = 0
	}
	if f.cursor >= len(f.rows) {
		f.cursor = len(f.rows) - 1
	}
}

func (m *model) cursorToFirstSelectable() {
	f := m.top()
	if f == nil {
		return
	}
	f.cursor, f.offset = 0, 0
	m.snapToSelectable(1)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// ---- view -------------------------------------------------------------------

var (
	styTitle    = lipgloss.NewStyle().Bold(true)
	styHeader   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	styCursor   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("11"))
	styDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	styMark     = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	styWarn     = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	styCrumb    = lipgloss.NewStyle().Foreground(lipgloss.Color("5"))
	styStatus   = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	styMetaKey  = lipgloss.NewStyle().Foreground(lipgloss.Color("4"))
	helpBrowse  = "↑↓ move · enter open · ← back · space mark · f filter galaxy · m marked · / search · q quit"
	helpSearchB = "enter search · esc cancel · ctrl+c quit"
)

func (m model) View() string {
	if m.quitting {
		return ""
	}
	var b strings.Builder

	// The corpus commit is on screen at all times, not tucked into a status
	// view: any finding taken out of here is only reproducible against the
	// exact corpus state it came from.
	header := styTitle.Render("misp-galaxy")
	if m.version != "" {
		header += " " + styDim.Render(m.version)
	}
	header += "  " + styDim.Render(fmt.Sprintf("%d galaxies in scope", len(m.scope)))
	if m.sourceRef != "" {
		ref := m.sourceRef
		if len(ref) > 12 {
			ref = ref[:12]
		}
		header += "  " + styDim.Render("corpus "+ref)
	}
	b.WriteString(header + "\n")

	if len(m.stack) > 0 {
		crumbs := make([]string, 0, len(m.stack))
		for _, f := range m.stack {
			crumbs = append(crumbs, f.title)
		}
		b.WriteString(styCrumb.Render(strings.Join(crumbs, " › ")))
		if f := m.top(); f != nil && f.galaxyFilter != "" {
			b.WriteString("  " + styMark.Render("["+f.galaxyFilter+"]"))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")

	if m.searching {
		b.WriteString(m.input.View() + "\n\n")
	}

	if f := m.top(); f != nil {
		if f.detail != nil {
			b.WriteString(m.renderDetail(f.detail))
		}
		b.WriteString(m.renderRows(f))
	}

	b.WriteString("\n")
	if m.err != "" {
		b.WriteString(styWarn.Render("error: "+m.err) + "\n")
	} else if m.status != "" {
		b.WriteString(styStatus.Render(m.status) + "\n")
	}
	if m.searching {
		b.WriteString(styDim.Render(helpSearchB))
	} else {
		b.WriteString(styDim.Render(helpBrowse))
	}
	return b.String()
}

func (m model) renderDetail(d *service.NodeDetail) string {
	var b strings.Builder
	width := m.width - 2
	if width < 40 {
		width = 78
	}

	head := d.Value + "  " + styDim.Render(d.Galaxy)
	if d.Revoked {
		head += "  " + styWarn.Render("[revoked]")
	}
	b.WriteString(styTitle.Render(head) + "\n")

	if d.Description != "" {
		desc := d.Description
		if len(desc) > 600 {
			desc = desc[:600] + "…"
		}
		b.WriteString(lipgloss.NewStyle().Width(width).Render(desc) + "\n")
	}
	if len(d.Synonyms) > 0 {
		b.WriteString(styMetaKey.Render("synonyms: ") +
			lipgloss.NewStyle().Width(width).Render(strings.Join(d.Synonyms, ", ")) + "\n")
	}
	b.WriteString(renderMeta(d.Meta, width))
	b.WriteString(styDim.Render(d.UUID) + "\n\n")
	return b.String()
}

// metaKeys are the meta fields worth surfacing, in display order. A reference
// entry without its URL tells you a report exists but not where to read it,
// which makes the last link of the malware → actor → report chain useless.
//
// meta is free-form across galaxies, so this is a curated shortlist rather
// than a dump: printing every key would bury the useful ones.
var metaKeys = []string{
	"refs", "official-refs", "date", "source", "country",
	"attribution-confidence", "cfr-suspected-state-sponsor",
	"external_id", "type", "status", "platform",
}

func renderMeta(meta map[string]any, width int) string {
	if len(meta) == 0 {
		return ""
	}
	var b strings.Builder
	for _, k := range metaKeys {
		v, ok := meta[k]
		if !ok {
			continue
		}
		text := flattenMeta(v)
		if text == "" {
			continue
		}
		b.WriteString(styMetaKey.Render(k+": ") +
			lipgloss.NewStyle().Width(width).Render(text) + "\n")
	}
	// Name the keys that exist but are not shown, so nothing looks absent when
	// it is merely unlisted.
	var others []string
	for k := range meta {
		if !slicesContains(metaKeys, k) {
			others = append(others, k)
		}
	}
	if len(others) > 0 {
		sortStrings(others)
		b.WriteString(styDim.Render("other meta: "+strings.Join(others, ", ")) + "\n")
	}
	return b.String()
}

func flattenMeta(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprintf("%g", t)
	case bool:
		return fmt.Sprintf("%t", t)
	case []any:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			if s := flattenMeta(item); s != "" {
				parts = append(parts, s)
			}
		}
		// References run long; show the first few and say how many remain.
		if len(parts) > 4 {
			return strings.Join(parts[:4], "\n") +
				fmt.Sprintf("\n(+%d more)", len(parts)-4)
		}
		return strings.Join(parts, "\n")
	default:
		return ""
	}
}

func slicesContains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func (m model) renderRows(f *frame) string {
	// Reserve room for the chrome: title, breadcrumb, blank lines, status, help
	// and, on a node frame, the detail block.
	avail := m.height - 8
	if f.detail != nil {
		avail -= 5 + strings.Count(m.renderDetail(f.detail), "\n")
	}
	if avail < 5 {
		avail = 5
	}

	// Keep the cursor inside the window.
	if f.cursor < f.offset {
		f.offset = f.cursor
	}
	if f.cursor >= f.offset+avail {
		f.offset = f.cursor - avail + 1
	}
	if f.offset < 0 {
		f.offset = 0
	}

	var b strings.Builder
	end := f.offset + avail
	if end > len(f.rows) {
		end = len(f.rows)
	}
	for i := f.offset; i < end; i++ {
		r := f.rows[i]
		if r.kind == rowHeader {
			b.WriteString("  " + styHeader.Render(r.label) + "\n")
			continue
		}
		cursor := "  "
		if i == f.cursor {
			cursor = styCursor.Render("▸ ")
		}
		box := "  "
		if m.marked[r.uuid] {
			box = styMark.Render("• ")
		}
		line := r.label
		if r.revoked {
			line += " " + styWarn.Render("[revoked]")
		}
		if r.note != "" && f.detail == nil {
			line += " " + styDim.Render("("+r.note+")")
		}
		if f.detail != nil && r.galaxy != "" {
			line += " " + styDim.Render(r.galaxy)
		}
		b.WriteString(cursor + box + line + "\n")
	}
	if end < len(f.rows) {
		b.WriteString(styDim.Render(fmt.Sprintf("  … %d more", len(f.rows)-end)) + "\n")
	}
	return b.String()
}
