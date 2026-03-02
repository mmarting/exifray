package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func init() { Register(&Wayback{}) }

// Wayback discovers file URLs via the Wayback Machine CDX API.
type Wayback struct{}

func (w *Wayback) Name() string  { return "wayback" }
func (w *Wayback) Label() string { return "Wayback Machine" }

func (w *Wayback) Discover(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	apiURL := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey",
		domain,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; exifray/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, err
	}

	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		// Might not be JSON array format — try line-based
		return parseLinesURLs(string(body)), nil
	}

	var urls []string
	for i, row := range rows {
		if i == 0 {
			continue // skip header row
		}
		if len(row) > 0 {
			u := strings.TrimSpace(row[0])
			if u != "" {
				urls = append(urls, u)
			}
		}
	}
	return urls, nil
}

func parseLinesURLs(body string) []string {
	var urls []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && (strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://")) {
			urls = append(urls, line)
		}
	}
	return urls
}
