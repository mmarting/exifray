package sources

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func init() { Register(&CommonCrawl{}) }

// CommonCrawl discovers file URLs via the Common Crawl Index API.
type CommonCrawl struct{}

func (c *CommonCrawl) Name() string  { return "commoncrawl" }
func (c *CommonCrawl) Label() string { return "Common Crawl" }

func (c *CommonCrawl) Discover(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	// Get the latest index
	index, err := c.latestIndex(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to get CC index: %w", err)
	}

	apiURL := fmt.Sprintf(
		"https://index.commoncrawl.org/%s-index?url=*.%s&output=json&fl=url",
		index, domain,
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

	var urls []string
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 10*1024*1024))
	for scanner.Scan() {
		var record struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			continue
		}
		if record.URL != "" {
			urls = append(urls, record.URL)
		}
	}
	return urls, scanner.Err()
}

func (c *CommonCrawl) latestIndex(ctx context.Context, client *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://index.commoncrawl.org/collinfo.json", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; exifray/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return "", err
	}

	var indexes []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &indexes); err != nil {
		return "", err
	}

	if len(indexes) == 0 {
		return "CC-MAIN-2025-08", nil // fallback
	}

	// The first entry is typically the most recent
	id := indexes[0].ID
	// Ensure the id doesn't already have "-index" suffix
	id = strings.TrimSuffix(id, "-index")
	return id, nil
}
