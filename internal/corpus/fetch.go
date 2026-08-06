package corpus

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
)

// UpstreamURL is where the corpus comes from when nothing else is specified.
const UpstreamURL = "https://github.com/MISP/misp-galaxy.git"

// Fetch puts a usable corpus in dir and returns the commit it checked out.
//
// This exists for the standalone binary: someone who downloads a release has
// no repository and no submodule, and should not have to reconstruct one by
// hand. It is a separate command rather than something the server does at
// startup — a server that clones 50,000 files on first launch looks like a
// hang, and an MCP client is waiting on the initialisation response while it
// happens.
//
// Cloning is shallow: the corpus is used as data, and its history is large and
// of no interest here.
func Fetch(ctx context.Context, dir, url, ref string) (string, error) {
	if url == "" {
		url = UpstreamURL
	}
	if dir == "" {
		return "", errors.New("corpus: no destination directory")
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return "", fmt.Errorf("corpus: preparing %s: %w", dir, err)
	}

	repo, err := git.PlainOpen(dir)
	switch {
	case err == nil:
		// Already there: update in place rather than re-cloning.
		if err := update(ctx, repo, ref); err != nil {
			return "", err
		}
	case errors.Is(err, git.ErrRepositoryNotExists):
		opts := &git.CloneOptions{URL: url, Depth: 1, SingleBranch: true}
		repo, err = git.PlainCloneContext(ctx, dir, false, opts)
		if err != nil {
			return "", fmt.Errorf("corpus: cloning %s: %w", url, err)
		}
		if ref != "" {
			if err := update(ctx, repo, ref); err != nil {
				return "", err
			}
		}
	default:
		return "", fmt.Errorf("corpus: opening %s: %w", dir, err)
	}

	head, err := repo.Head()
	if err != nil {
		return "", fmt.Errorf("corpus: reading HEAD: %w", err)
	}
	return head.Hash().String(), nil
}

// update moves an existing checkout: to ref when given, otherwise to the tip of
// the tracked branch.
func update(ctx context.Context, repo *git.Repository, ref string) error {
	wt, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("corpus: worktree: %w", err)
	}

	if ref == "" {
		err = wt.PullContext(ctx, &git.PullOptions{RemoteName: "origin", Depth: 1})
		if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
			return fmt.Errorf("corpus: pulling: %w", err)
		}
		return nil
	}

	// A specific commit may not be in a shallow clone, so fetch it explicitly
	// before checking it out.
	fetchErr := repo.FetchContext(ctx, &git.FetchOptions{
		RemoteName: "origin",
		Depth:      1,
		RefSpecs:   []config.RefSpec{config.RefSpec(ref + ":refs/corpus/pinned")},
	})
	if fetchErr != nil && !errors.Is(fetchErr, git.NoErrAlreadyUpToDate) {
		// Not fatal: the commit may already be present locally.
		if _, err := repo.CommitObject(plumbing.NewHash(ref)); err != nil {
			return fmt.Errorf("corpus: fetching %s: %w", ref, fetchErr)
		}
	}
	if err := wt.Checkout(&git.CheckoutOptions{
		Hash:  plumbing.NewHash(ref),
		Force: true,
	}); err != nil {
		return fmt.Errorf("corpus: checking out %s: %w", ref, err)
	}
	return nil
}

// HeadOf returns the commit checked out in a standalone corpus directory, or
// an empty string when it is not a git repository. Used for provenance when
// the corpus was fetched rather than vendored as a submodule.
func HeadOf(dir string) string {
	repo, err := git.PlainOpen(dir)
	if err != nil {
		return ""
	}
	head, err := repo.Head()
	if err != nil {
		return ""
	}
	return head.Hash().String()
}

// Usable reports whether dir looks like a loadable corpus.
func Usable(dir string) bool {
	entries, err := os.ReadDir(filepath.Join(dir, "clusters"))
	return err == nil && len(entries) > 0
}

// DefaultDataDir is where a standalone binary keeps its corpus when no path is
// given: the XDG data directory, falling back to ~/.local/share.
func DefaultDataDir() string {
	if base := os.Getenv("XDG_DATA_HOME"); base != "" {
		return filepath.Join(base, "misp-galaxy")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "misp-galaxy"
	}
	return filepath.Join(home, ".local", "share", "misp-galaxy")
}
