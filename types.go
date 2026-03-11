package main

import "time"

// Version info
const Version = "1.0.0"

// Severity levels for findings
type Severity string

const (
	SeverityInfo        Severity = "info"
	SeverityInteresting Severity = "interesting"
	SeverityNotable     Severity = "notable"
)

// Finding categories
type FindingCategory string

const (
	CategoryGPS      FindingCategory = "GPS"
	CategoryUser     FindingCategory = "Users"
	CategoryEmail    FindingCategory = "Emails"
	CategorySoftware FindingCategory = "Software"
	CategoryPrinter  FindingCategory = "Printers"
	CategorySerial   FindingCategory = "Serials"
	CategoryPath     FindingCategory = "Paths"
	CategoryURL      FindingCategory = "URLs"
	CategoryHostname FindingCategory = "Hostnames"
)

// MetadataResult holds extracted metadata from a single file.
type MetadataResult struct {
	URL    string            `json:"url"`
	Fields map[string]string `json:"fields,omitempty"`
	Error  string            `json:"error,omitempty"`
}

// Finding represents an interesting piece of metadata.
type Finding struct {
	Category FindingCategory `json:"category"`
	Severity Severity        `json:"severity"`
	File     string          `json:"file"`
	Details  map[string]string `json:"details"`
}

// JSONOutput is the top-level structure for --json output.
type JSONOutput struct {
	Version       string            `json:"version"`
	Timestamp     string            `json:"timestamp"`
	Domain        string            `json:"domain"`
	URLsDiscovered int              `json:"urls_discovered"`
	FilesAnalyzed  int              `json:"files_analyzed"`
	Findings      []Finding         `json:"findings"`
	Metadata      []MetadataResult  `json:"metadata"`
	Sources       map[string]int    `json:"sources"`
}

// SourceResult tracks discovery results per source.
type SourceResult struct {
	Name  string
	Label string
	Count int
	Err   error
}

// Config holds parsed CLI configuration.
type Config struct {
	Domains    []string
	Workers    int
	Timeout    time.Duration
	MaxRetries int
	RetryDelay time.Duration
	Verbose    bool
	Quiet      bool
	JSON       bool
	Output     string
	Proxy      string
	RateLimit  float64
	Extensions []string
	Sources    []string
	ShowURLs   bool
	URLsFile   string
}

// Default file extensions to look for.
var DefaultExtensions = []string{
	// Images
	".jpg", ".jpeg", ".png", ".gif", ".tiff", ".tif", ".bmp", ".webp", ".svg",
	// Documents
	".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp",
	// Media
	".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv",
}
