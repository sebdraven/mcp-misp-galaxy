// Package corpus drives the misp-galaxy git submodule from Go, so the data
// checkout is managed by the application rather than by the operator.
//
// Two operations, deliberately kept apart:
//
//	Sync    brings the submodule to the commit the parent repo pins. Idempotent,
//	        safe to run at every boot, and it never changes what you are looking
//	        at — that is the point of pinning.
//	Advance moves the submodule to the tip of its remote branch. It leaves the
//	        parent's submodule pointer dirty on purpose: bumping the corpus is a
//	        decision that belongs in a commit, not a side effect of starting up.
//
// The distinction matters for CTI work. A name resolution that silently shifts
// between two runs is not reproducible, so freshness has to be an explicit act.
package corpus

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// SubmodulePath is where the misp-galaxy submodule lives inside the parent
// repository.
const SubmodulePath = "data/misp-galaxy"

// Manager owns the parent repository and the submodule under it.
//
// The repository may be absent: in a container image the corpus is baked in as
// plain files, with no .git anywhere. That is a supported deployment, not an
// error, so the manager degrades to unavailable and the caller loads whatever
// is on disk. Only the git operations become impossible.
type Manager struct {
	root      string // parent repository working tree
	name      string // submodule name as declared in .gitmodules
	available bool
}

// ErrNoRepo is returned by the git operations when no repository backs the
// checkout.
var ErrNoRepo = errors.New("corpus: no git repository at the configured root")

// NewManager opens the repository at root. A missing or unreadable repository
// is not fatal — see Available.
func NewManager(root, submodule string) (*Manager, error) {
	if submodule == "" {
		submodule = SubmodulePath
	}
	m := &Manager{root: root, name: submodule}
	if _, err := git.PlainOpen(root); err == nil {
		m.available = true
	}
	return m, nil
}

// Available reports whether git operations are possible. When false, Sync,
// Advance and Head all fail, but the corpus on disk is still loadable.
func (m *Manager) Available() bool { return m.available }

// DataDir is the absolute path of the checked-out corpus.
func (m *Manager) DataDir() string { return filepath.Join(m.root, m.name) }

// State describes where the submodule currently stands.
type State struct {
	Path     string `json:"path"`
	Expected string `json:"expected" jsonschema:"commit the parent repository pins"`
	Current  string `json:"current" jsonschema:"commit actually checked out"`
	InSync   bool   `json:"in_sync"`
	Ready    bool   `json:"ready" jsonschema:"whether the checkout holds usable data"`
}

// Status reports the submodule state without touching anything.
func (m *Manager) Status() (State, error) {
	if !m.available {
		// Still worth answering: whether the data is usable matters more than
		// whether git can describe it.
		return State{Path: m.DataDir(), Ready: m.hasClusters()}, nil
	}
	sub, err := m.submodule()
	if err != nil {
		return State{}, err
	}
	st, err := sub.Status()
	if err != nil {
		return State{}, fmt.Errorf("corpus: submodule status: %w", err)
	}
	s := State{
		Path:     m.DataDir(),
		Expected: st.Expected.String(),
		Current:  st.Current.String(),
		InSync:   st.Current == st.Expected && st.Current != plumbing.ZeroHash,
	}
	s.Ready = m.hasClusters()
	return s, nil
}

// Sync initialises the submodule if needed and checks out the pinned commit.
// Safe to call on every start: when everything already matches it does nothing.
func (m *Manager) Sync() (State, error) {
	sub, err := m.submodule()
	if err != nil {
		return State{}, err
	}
	// Init is idempotent; an already-initialised submodule reports
	// ErrSubmoduleAlreadyInitialized, which is not a failure here.
	if err := sub.Init(); err != nil && !errors.Is(err, git.ErrSubmoduleAlreadyInitialized) {
		return State{}, fmt.Errorf("corpus: submodule init: %w", err)
	}
	if err := sub.Update(&git.SubmoduleUpdateOptions{Init: true}); err != nil &&
		!errors.Is(err, git.NoErrAlreadyUpToDate) {
		return State{}, fmt.Errorf("corpus: submodule update: %w", err)
	}
	return m.Status()
}

// Advance fetches the submodule's remote and moves the checkout to the tip of
// branch (empty means the remote's default). The parent repository's pointer is
// left dirty; committing that bump is the caller's decision.
func (m *Manager) Advance(branch string) (State, error) {
	sub, err := m.submodule()
	if err != nil {
		return State{}, err
	}
	repo, err := sub.Repository()
	if err != nil {
		return State{}, fmt.Errorf("corpus: opening submodule repository: %w", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		return State{}, fmt.Errorf("corpus: submodule worktree: %w", err)
	}
	opts := &git.PullOptions{RemoteName: "origin"}
	if branch != "" {
		opts.ReferenceName = plumbing.NewBranchReferenceName(branch)
	}
	if err := wt.Pull(opts); err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return State{}, fmt.Errorf("corpus: pulling submodule: %w", err)
	}
	return m.Status()
}

// Head returns the commit currently checked out in the submodule, for stamping
// a built graph with the corpus state it came from. Empty when no repository
// backs the checkout — provenance then has to come from elsewhere, which is
// what GALAXY_CORPUS_REF is for in container images.
func (m *Manager) Head() (string, error) {
	if !m.available {
		return "", ErrNoRepo
	}
	sub, err := m.submodule()
	if err != nil {
		return "", err
	}
	repo, err := sub.Repository()
	if err != nil {
		return "", err
	}
	ref, err := repo.Head()
	if err != nil {
		return "", err
	}
	return ref.Hash().String(), nil
}

func (m *Manager) submodule() (*git.Submodule, error) {
	if !m.available {
		return nil, ErrNoRepo
	}
	repo, err := git.PlainOpen(m.root)
	if err != nil {
		return nil, fmt.Errorf("corpus: opening %s: %w", m.root, err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("corpus: worktree: %w", err)
	}
	sub, err := wt.Submodule(m.name)
	if err != nil {
		return nil, fmt.Errorf("corpus: submodule %q (declared in .gitmodules?): %w", m.name, err)
	}
	return sub, nil
}

// hasClusters is the cheap readiness test: an initialised-but-empty submodule
// directory is the usual failure mode and it is invisible from git status.
func (m *Manager) hasClusters() bool {
	entries, err := os.ReadDir(filepath.Join(m.DataDir(), "clusters"))
	return err == nil && len(entries) > 0
}
