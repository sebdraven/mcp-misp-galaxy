// Package httpapi is the REST façade. It maps query parameters onto
// service calls and serialises the result; no query logic lives here.
package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/sebdraven/mcp-misp-galaxy/internal/galaxy"
	"github.com/sebdraven/mcp-misp-galaxy/internal/service"
)

// Handler builds the REST mux.
func Handler(s *service.Service) http.Handler {
	mux := http.NewServeMux()
	h := &handlers{s: s}

	mux.HandleFunc("GET /resolve", h.resolve)
	mux.HandleFunc("GET /node/{uuid}", h.node)
	mux.HandleFunc("GET /refs/{uuid}", h.refs)
	mux.HandleFunc("GET /profile/{uuid}", h.profile)
	mux.HandleFunc("GET /cooccurrence/{uuid}", h.cooccurrence)
	mux.HandleFunc("GET /neighbors/{uuid}", h.neighbours)
	mux.HandleFunc("GET /path", h.path)
	mux.HandleFunc("GET /galaxies", h.galaxies)
	mux.HandleFunc("GET /generic", h.generic)
	mux.HandleFunc("GET /status", h.status)

	// Mutating the corpus is a POST: it changes what every subsequent answer
	// says, which should not be reachable by following a link.
	mux.HandleFunc("POST /admin/sync", h.sync)
	mux.HandleFunc("POST /admin/advance", h.advance)
	mux.HandleFunc("POST /admin/reload", h.reload)

	return mux
}

type handlers struct{ s *service.Service }

func (h *handlers) resolve(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	name := q.Get("q")
	if strings.TrimSpace(name) == "" {
		fail(w, http.StatusBadRequest, "q is required")
		return
	}
	group := q.Get("group") == "1" || q.Get("group") == "true"
	res, err := h.s.Resolve(name, csv(q.Get("galaxy")), intParam(r, "limit", 0), group, q.Get("normalisation"))
	respond(w, res, err)
}

func (h *handlers) node(w http.ResponseWriter, r *http.Request) {
	res, err := h.s.Node(r.PathValue("uuid"))
	respond(w, res, err)
}

func (h *handlers) refs(w http.ResponseWriter, r *http.Request) {
	res, err := h.s.Refs(r.PathValue("uuid"))
	respond(w, res, err)
}

func (h *handlers) profile(w http.ResponseWriter, r *http.Request) {
	res, err := h.s.Profile(r.PathValue("uuid"), intParam(r, "depth", 1), intParam(r, "limit", 0))
	respond(w, res, err)
}

func (h *handlers) cooccurrence(w http.ResponseWriter, r *http.Request) {
	rate := 0.0
	if v := r.URL.Query().Get("min_rate"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			rate = f
		}
	}
	res, err := h.s.CoOccurrence(r.PathValue("uuid"), rate, intParam(r, "limit", 0))
	respond(w, res, err)
}

func (h *handlers) neighbours(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	opt := galaxy.NeighbourOpts{
		Depth:         intParam(r, "depth", 1),
		Direction:     galaxy.Direction(q.Get("direction")),
		EdgeTypes:     csv(q.Get("type")),
		Galaxies:      csv(q.Get("galaxy")),
		MaxGroupCount: intParam(r, "max_group_count", 0),
		Limit:         intParam(r, "limit", 0),
		WithPaths:     q.Get("paths") == "1" || q.Get("paths") == "true",
		SkipGhosts:    q.Get("skip_dangling") == "1" || q.Get("skip_dangling") == "true",
	}
	res, err := h.s.Neighbours(r.PathValue("uuid"), opt)
	respond(w, res, err)
}

func (h *handlers) path(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from, to := q.Get("from"), q.Get("to")
	if from == "" || to == "" {
		fail(w, http.StatusBadRequest, "from and to are required")
		return
	}
	res, err := h.s.Path(from, to, intParam(r, "max_depth", 0), csv(q.Get("type")))
	respond(w, res, err)
}

func (h *handlers) galaxies(w http.ResponseWriter, r *http.Request) {
	res, err := h.s.Galaxies()
	respond(w, res, err)
}

func (h *handlers) generic(w http.ResponseWriter, r *http.Request) {
	res, err := h.s.MostGeneric(r.URL.Query().Get("galaxy"), intParam(r, "limit", 0))
	respond(w, res, err)
}

func (h *handlers) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.s.Status())
}

func (h *handlers) sync(w http.ResponseWriter, r *http.Request) {
	res, err := h.s.Sync()
	respond(w, res, err)
}

func (h *handlers) advance(w http.ResponseWriter, r *http.Request) {
	res, err := h.s.Advance(r.URL.Query().Get("branch"))
	respond(w, res, err)
}

func (h *handlers) reload(w http.ResponseWriter, r *http.Request) {
	res, err := h.s.Reload()
	respond(w, res, err)
}

// ---- plumbing ---------------------------------------------------------------

func respond(w http.ResponseWriter, payload any, err error) {
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, payload)
	case errors.Is(err, service.ErrUnknownNode):
		fail(w, http.StatusNotFound, err.Error())
	case errors.Is(err, service.ErrUnknownNormalisation):
		fail(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, service.ErrNotLoaded):
		// Distinct from a plain 500: the service is up, the corpus is not
		// ready yet. Retrying later is the right response.
		fail(w, http.StatusServiceUnavailable, err.Error())
	default:
		fail(w, http.StatusInternalServerError, err.Error())
	}
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(payload)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func intParam(r *http.Request, name string, def int) int {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func csv(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
