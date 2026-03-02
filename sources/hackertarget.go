package sources

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func init() { Register(&HackerTarget{}) }

// HackerTarget discovers file URLs via the HackerTarget page links API.
type HackerTarget struct{}

func (h *HackerTarget) Name() string  { return "hackertarget" }
func (h *HackerTarget) Label() string { return "HackerTarget" }

func (h *HackerTarget) Discover(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	apiURL := fmt.Sprintf("https://api.hackertarget.com/pagelinks/?q=%s", domain)

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
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 5*1024*1024))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// API returns one URL per line
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			urls = append(urls, line)
		}
		// Error responses from the free API
		if strings.Contains(line, "API count exceeded") || strings.Contains(line, "error") {
			if len(urls) == 0 {
				return nil, fmt.Errorf("%s", line)
			}
			break
		}
	}

	return urls, scanner.Err()
}
