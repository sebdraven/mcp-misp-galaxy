package corpus

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// clustersIn makes a directory look like a usable corpus checkout.
func clustersIn(t *testing.T, dir string) {
	t.Helper()
	clusters := filepath.Join(dir, "clusters")
	if err := os.MkdirAll(clusters, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(clusters, "x.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestManagerWithoutRepository(t *testing.T) {
	// A container image has no .git anywhere. That is a supported deployment,
	// so the manager degrades instead of refusing to exist.
	root := t.TempDir()
	clustersIn(t, filepath.Join(root, SubmodulePath))

	m, err := NewManager(root, "")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if m.Available() {
		t.Error("no repository at root, git operations should be unavailable")
	}

	st, err := m.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.Ready {
		t.Error("the corpus on disk is usable and Status should say so")
	}
	if _, err := m.Head(); err == nil {
		t.Error("Head should fail without a repository")
	}
}

func TestStatusReportsUsableCorpusWithoutGit(t *testing.T) {
	// Ready is the question that matters at startup — whether the data can be
	// loaded — and it must be answerable without git.
	root := t.TempDir()
	m, _ := NewManager(root, "")

	st, err := m.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Ready {
		t.Error("an empty checkout is not ready")
	}

	clustersIn(t, filepath.Join(root, SubmodulePath))
	st, err = m.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.Ready {
		t.Error("a populated checkout is ready")
	}
}

func TestSyncFailsWithoutARepository(t *testing.T) {
	// Sync is a git operation, so it reports that git is unavailable rather
	// than pretending to have synced. The caller decides whether to carry on
	// with the data on disk — which is exactly what the container path does.
	root := t.TempDir()
	clustersIn(t, filepath.Join(root, SubmodulePath))
	m, _ := NewManager(root, "")

	if _, err := m.Sync(); !errors.Is(err, ErrNoRepo) {
		t.Errorf("Sync without a repository should report ErrNoRepo, got %v", err)
	}

	// And the corpus stays loadable: an unavailable git is not unusable data.
	st, err := m.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.Ready {
		t.Error("the corpus on disk remains loadable even when git cannot run")
	}
}

func TestDataDir(t *testing.T) {
	m, _ := NewManager("/some/root", "")
	if got, want := m.DataDir(), filepath.Join("/some/root", SubmodulePath); got != want {
		t.Errorf("DataDir() = %q, want %q", got, want)
	}
	m2, _ := NewManager("/some/root", "elsewhere/data")
	if got, want := m2.DataDir(), "/some/root/elsewhere/data"; got != want {
		t.Errorf("DataDir() = %q, want %q", got, want)
	}
}
