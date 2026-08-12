package service

import (
	"errors"
	"testing"

	"github.com/sebdraven/mcp-misp-galaxy/internal/galaxy"
)

func TestParseNormalisationAcceptsKnownModes(t *testing.T) {
	cases := map[string]galaxy.Normalisation{
		"":           galaxy.Standard, // omitted by the caller
		"standard":   galaxy.Standard,
		"Standard":   galaxy.Standard,
		"  standard": galaxy.Standard,
		"aggressive": galaxy.Aggressive,
		"AGGRESSIVE": galaxy.Aggressive,
	}
	for in, want := range cases {
		got, err := parseNormalisation(in)
		if err != nil {
			t.Errorf("parseNormalisation(%q) returned %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseNormalisation(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseNormalisationRejectsUnknownMode(t *testing.T) {
	// The failure this guards against is silent: defaulting a misspelt mode to
	// standard returns a plausible answer under the wrong folding, and the
	// caller reads it as "aggressive found nothing extra".
	for _, in := range []string{"agressive", "loose", "true", "1"} {
		if _, err := parseNormalisation(in); !errors.Is(err, ErrUnknownNormalisation) {
			t.Errorf("parseNormalisation(%q) error = %v, want ErrUnknownNormalisation", in, err)
		}
	}
}
