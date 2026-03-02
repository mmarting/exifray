package sources

import (
	"context"
	"net/http"
	"sort"
	"strings"
)

// Source defines the interface every discovery plugin must implement.
type Source interface {
	Name() string
	Label() string
	Discover(ctx context.Context, domain string, client *http.Client) ([]string, error)
}

var registry []Source

// apiKeys holds API keys set from the config file.
var apiKeys = make(map[string]string)

// Register adds a source to the global registry. Called from init() in each source file.
func Register(s Source) {
	registry = append(registry, s)
}

// needsAPI lists source names that require API keys.
var needsAPI = map[string]bool{
	"virustotal": true,
	"google":     true,
}

// All returns all registered sources, sorted: free sources first, API sources last.
func All() []Source {
	sorted := make([]Source, len(registry))
	copy(sorted, registry)
	sort.SliceStable(sorted, func(i, j int) bool {
		ai := needsAPI[sorted[i].Name()]
		aj := needsAPI[sorted[j].Name()]
		if ai != aj {
			return !ai
		}
		return false
	})
	return sorted
}

// SetAPIKeys sets API keys that sources can use.
func SetAPIKeys(keys map[string]string) {
	apiKeys = keys
}

// GetAPIKey returns the API key for the given key name.
func GetAPIKey(name string) string {
	return apiKeys[name]
}

// ErrNeedsConfig is returned when a source requires API configuration.
type ErrNeedsConfig struct {
	Hint string
}

func (e *ErrNeedsConfig) Error() string {
	return e.Hint
}

// FilterByName returns only the sources whose Name() matches one of the given names.
// If names contains "all", returns all sources.
func FilterByName(names []string) []Source {
	for _, n := range names {
		if strings.ToLower(n) == "all" {
			return registry
		}
	}
	nameSet := make(map[string]bool)
	for _, n := range names {
		nameSet[strings.ToLower(strings.TrimSpace(n))] = true
	}
	var filtered []Source
	for _, s := range registry {
		if nameSet[s.Name()] {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

// IsEnabled checks if a source name is in the enabled list.
func IsEnabled(name string, enabled []Source) bool {
	for _, s := range enabled {
		if s.Name() == name {
			return true
		}
	}
	return false
}
