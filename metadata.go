package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/rwcarlsen/goexif/exif"
)

const maxFileSize = 50 * 1024 * 1024 // 50MB

// extractMetadata fetches a URL with retry logic for transient errors.
func extractMetadata(url string, client *http.Client, timeout time.Duration, maxRetries int, retryDelay time.Duration) MetadataResult {
	var result MetadataResult
	for attempt := 0; attempt <= maxRetries; attempt++ {
		result = extractMetadataOnce(url, client, timeout)
		if result.Error == "" || !isRetryableError(result.Error) {
			return result
		}
		if attempt < maxRetries {
			time.Sleep(retryDelay * time.Duration(attempt+1))
		}
	}
	return result
}

// isRetryableError returns true for transient errors worth retrying:
// timeouts, client cancellations, and HTTP 429/502/503/504 responses.
func isRetryableError(errStr string) bool {
	return strings.Contains(errStr, "deadline exceeded") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "i/o timeout") ||
		strings.Contains(errStr, "request canceled") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "HTTP 429") ||
		strings.Contains(errStr, "HTTP 502") ||
		strings.Contains(errStr, "HTTP 503") ||
		strings.Contains(errStr, "HTTP 504")
}

// extractMetadataOnce fetches a URL and extracts metadata based on file type.
func extractMetadataOnce(url string, client *http.Client, timeout time.Duration) MetadataResult {
	result := MetadataResult{
		URL:    url,
		Fields: make(map[string]string),
	}

	ext := strings.ToLower(path.Ext(urlPath(url)))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return result
	}

	// Extract interesting HTTP headers
	extractHTTPHeaders(resp.Header, &result)

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFileSize))
	if err != nil {
		result.Error = err.Error()
		return result
	}

	if len(data) == 0 {
		result.Error = "empty response"
		return result
	}

	switch ext {
	case ".jpg", ".jpeg":
		extractEXIF(data, &result)
	case ".tiff", ".tif":
		extractEXIF(data, &result)
	case ".png":
		extractPNG(data, &result)
	case ".gif":
		extractGIF(data, &result)
	case ".webp":
		extractWebP(data, &result)
	case ".pdf":
		extractPDF(data, &result)
	case ".docx":
		extractOOXML(data, &result)
	case ".xlsx":
		extractOOXML(data, &result)
	case ".pptx":
		extractOOXML(data, &result)
	case ".odt", ".ods", ".odp":
		extractODF(data, &result)
	case ".svg":
		extractSVG(data, &result)
	case ".mp3":
		extractMP3(data, &result)
	case ".doc", ".xls", ".ppt":
		extractOLE(data, &result)
	default:
		extractEXIF(data, &result)
	}

	// Try XMP on any file type — XMP can be embedded in many formats
	extractXMP(data, &result)

	// Clean all extracted values
	cleanFields(&result)

	return result
}

// extractHTTPHeaders captures metadata-relevant HTTP response headers.
func extractHTTPHeaders(headers http.Header, result *MetadataResult) {
	interesting := []struct {
		header string
		field  string
	}{
		{"Server", "HTTPServer"},
		{"X-Powered-By", "HTTPPoweredBy"},
		{"X-Generator", "HTTPGenerator"},
		{"X-AspNet-Version", "HTTPAspNetVersion"},
	}

	// Generic server values that aren't useful for metadata discovery
	boringServers := map[string]bool{
		"cloudflare": true, "nginx": true, "apache": true,
		"akamaighost": true, "akamainetstorage": true,
		"cloudfront": true, "gws": true, "gse": true,
		"microsoft-iis": true, "gunicorn": true, "openresty": true,
		"amazons3": true, "awselb": true, "elb": true,
		"varnish": true, "squid": true, "envoy": true,
		"lighttpd": true, "caddy": true, "tengine": true,
		"litespeed": true, "cowboy": true, "fastly": true,
	}

	for _, h := range interesting {
		val := headers.Get(h.header)
		if val == "" {
			continue
		}
		// Skip boring/generic server names for the Server header
		if h.header == "Server" && boringServers[strings.ToLower(strings.TrimSpace(val))] {
			continue
		}
		result.Fields[h.field] = val
	}
}

func urlPath(rawURL string) string {
	// Extract path from URL, handling query params
	idx := strings.Index(rawURL, "?")
	if idx != -1 {
		rawURL = rawURL[:idx]
	}
	idx = strings.LastIndex(rawURL, "/")
	if idx != -1 {
		return rawURL[idx:]
	}
	return rawURL
}

// extractEXIF extracts EXIF metadata from JPEG/TIFF data.
func extractEXIF(data []byte, result *MetadataResult) {
	x, err := exif.Decode(bytes.NewReader(data))
	if err != nil {
		return
	}

	tags := []string{
		"Make", "Model", "Software", "Artist", "Copyright",
		"ImageDescription", "DateTime", "DateTimeOriginal",
		"GPSLatitude", "GPSLongitude", "GPSLatitudeRef", "GPSLongitudeRef",
		"XPAuthor", "XPComment", "XPKeywords",
		"HostComputer", "CameraSerialNumber",
		"BodySerialNumber", "LensSerialNumber", "InternalSerialNumber",
		"ImageUniqueID",
	}

	for _, tag := range tags {
		t, err := x.Get(exif.FieldName(tag))
		if err != nil {
			continue
		}
		val := strings.TrimSpace(t.String())
		val = strings.Trim(val, "\"")
		if val != "" && val != "0" {
			result.Fields[tag] = val
		}
	}

	// Extract GPS coordinates as decimal degrees
	lat, lon, err := x.LatLong()
	if err == nil {
		result.Fields["GPSLatitude"] = fmt.Sprintf("%.6f", lat)
		result.Fields["GPSLongitude"] = fmt.Sprintf("%.6f", lon)
	}
}

// extractPNG extracts text chunks from PNG files.
func extractPNG(data []byte, result *MetadataResult) {
	if len(data) < 8 {
		return
	}
	// PNG signature: 137 80 78 71 13 10 26 10
	if !bytes.Equal(data[:8], []byte{137, 80, 78, 71, 13, 10, 26, 10}) {
		return
	}

	offset := 8
	for offset+12 <= len(data) {
		length := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		chunkType := string(data[offset+4 : offset+8])

		if length < 0 || offset+12+length > len(data) {
			break
		}

		chunkData := data[offset+8 : offset+8+length]

		switch chunkType {
		case "tEXt":
			parts := bytes.SplitN(chunkData, []byte{0}, 2)
			if len(parts) == 2 {
				key := string(parts[0])
				val := string(parts[1])
				if key != "" && val != "" {
					result.Fields[key] = val
				}
			}
		case "iTXt":
			// iTXt: keyword\0 compression_flag compression_method language\0 translated_keyword\0 text
			nullIdx := bytes.IndexByte(chunkData, 0)
			if nullIdx > 0 && nullIdx+3 < len(chunkData) {
				key := string(chunkData[:nullIdx])
				rest := chunkData[nullIdx+3:] // skip null, compression flag, method
				// Find language tag end
				langEnd := bytes.IndexByte(rest, 0)
				if langEnd >= 0 && langEnd+1 < len(rest) {
					rest = rest[langEnd+1:]
					// Find translated keyword end
					tkEnd := bytes.IndexByte(rest, 0)
					if tkEnd >= 0 && tkEnd+1 < len(rest) {
						val := string(rest[tkEnd+1:])
						if key != "" && val != "" {
							result.Fields[key] = val
						}
					}
				}
			}
		case "IEND":
			return
		}

		offset += 12 + length // 4 length + 4 type + data + 4 CRC
	}
}

// extractPDF extracts metadata from the /Info dictionary.
func extractPDF(data []byte, result *MetadataResult) {
	content := string(data)

	keys := []string{"Author", "Creator", "Producer", "Title", "Subject", "CreationDate", "ModDate", "Keywords"}
	for _, key := range keys {
		val := pdfExtractField(content, key)
		if val != "" {
			result.Fields[key] = val
		}
	}
}

func pdfExtractField(content, key string) string {
	// Look for /Key (value) or /Key <hex>
	search := "/" + key
	idx := strings.Index(content, search)
	if idx == -1 {
		return ""
	}

	rest := content[idx+len(search):]
	rest = strings.TrimLeft(rest, " \t\r\n")

	if len(rest) == 0 {
		return ""
	}

	if rest[0] == '(' {
		// Parenthesized string
		depth := 0
		var result []byte
		for i := 0; i < len(rest); i++ {
			ch := rest[i]
			if ch == '(' {
				if depth > 0 {
					result = append(result, ch)
				}
				depth++
			} else if ch == ')' {
				depth--
				if depth == 0 {
					return string(result)
				}
				result = append(result, ch)
			} else if ch == '\\' && i+1 < len(rest) {
				i++
				result = append(result, rest[i])
			} else {
				if depth > 0 {
					result = append(result, ch)
				}
			}
		}
	} else if rest[0] == '<' && (len(rest) < 2 || rest[1] != '<') {
		// Hex string
		end := strings.IndexByte(rest, '>')
		if end > 1 {
			hex := rest[1:end]
			return decodeHexString(hex)
		}
	}

	return ""
}

func decodeHexString(hexStr string) string {
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	hexStr = strings.ReplaceAll(hexStr, "\n", "")
	hexStr = strings.ReplaceAll(hexStr, "\r", "")

	var raw []byte
	for i := 0; i+1 < len(hexStr); i += 2 {
		var b byte
		fmt.Sscanf(hexStr[i:i+2], "%02x", &b)
		raw = append(raw, b)
	}

	return decodeBytes(raw)
}

// decodeBytes handles UTF-16BE (BOM: FE FF), UTF-16LE (BOM: FF FE), or raw bytes.
func decodeBytes(raw []byte) string {
	if len(raw) >= 2 && raw[0] == 0xFE && raw[1] == 0xFF {
		// UTF-16BE
		return decodeUTF16BE(raw[2:])
	}
	if len(raw) >= 2 && raw[0] == 0xFF && raw[1] == 0xFE {
		// UTF-16LE
		return decodeUTF16LE(raw[2:])
	}
	// Strip null bytes, assume Latin-1/UTF-8
	var clean []byte
	for _, b := range raw {
		if b != 0 {
			clean = append(clean, b)
		}
	}
	return string(clean)
}

func decodeUTF16BE(data []byte) string {
	var codepoints []uint16
	for i := 0; i+1 < len(data); i += 2 {
		cp := uint16(data[i])<<8 | uint16(data[i+1])
		if cp == 0 {
			break
		}
		codepoints = append(codepoints, cp)
	}
	return string(utf16.Decode(codepoints))
}

func decodeUTF16LE(data []byte) string {
	var codepoints []uint16
	for i := 0; i+1 < len(data); i += 2 {
		cp := uint16(data[i]) | uint16(data[i+1])<<8
		if cp == 0 {
			break
		}
		codepoints = append(codepoints, cp)
	}
	return string(utf16.Decode(codepoints))
}

// extractOOXML extracts metadata from Office Open XML files (.docx, .xlsx, .pptx).
func extractOOXML(data []byte, result *MetadataResult) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return
	}

	for _, f := range r.File {
		switch f.Name {
		case "docProps/core.xml":
			extractOOXMLCore(f, result)
		case "docProps/app.xml":
			extractOOXMLApp(f, result)
		}
	}
}

func extractOOXMLCore(f *zip.File, result *MetadataResult) {
	rc, err := f.Open()
	if err != nil {
		return
	}
	defer rc.Close()

	data, err := io.ReadAll(io.LimitReader(rc, 1*1024*1024))
	if err != nil {
		return
	}

	var core struct {
		Creator     string `xml:"creator"`
		LastModBy   string `xml:"lastModifiedBy"`
		Created     string `xml:"created"`
		Modified    string `xml:"modified"`
		Title       string `xml:"title"`
		Subject     string `xml:"subject"`
		Description string `xml:"description"`
		Keywords    string `xml:"keywords"`
		Revision    string `xml:"revision"`
	}

	if err := xml.Unmarshal(data, &core); err != nil {
		// Try a more lenient approach — look for tags manually
		content := string(data)
		setIfFound(result, "Creator", xmlExtract(content, "dc:creator"))
		setIfFound(result, "LastModifiedBy", xmlExtract(content, "cp:lastModifiedBy"))
		setIfFound(result, "Created", xmlExtract(content, "dcterms:created"))
		setIfFound(result, "Modified", xmlExtract(content, "dcterms:modified"))
		setIfFound(result, "Title", xmlExtract(content, "dc:title"))
		setIfFound(result, "Subject", xmlExtract(content, "dc:subject"))
		setIfFound(result, "Description", xmlExtract(content, "dc:description"))
		setIfFound(result, "Keywords", xmlExtract(content, "cp:keywords"))
		setIfFound(result, "Revision", xmlExtract(content, "cp:revision"))
		return
	}

	setIfFound(result, "Creator", core.Creator)
	setIfFound(result, "LastModifiedBy", core.LastModBy)
	setIfFound(result, "Created", core.Created)
	setIfFound(result, "Modified", core.Modified)
	setIfFound(result, "Title", core.Title)
	setIfFound(result, "Subject", core.Subject)
	setIfFound(result, "Description", core.Description)
	setIfFound(result, "Keywords", core.Keywords)
	setIfFound(result, "Revision", core.Revision)
}

func extractOOXMLApp(f *zip.File, result *MetadataResult) {
	rc, err := f.Open()
	if err != nil {
		return
	}
	defer rc.Close()

	data, err := io.ReadAll(io.LimitReader(rc, 1*1024*1024))
	if err != nil {
		return
	}

	content := string(data)
	setIfFound(result, "Application", xmlExtract(content, "Application"))
	setIfFound(result, "AppVersion", xmlExtract(content, "AppVersion"))
	setIfFound(result, "Company", xmlExtract(content, "Company"))
	setIfFound(result, "Manager", xmlExtract(content, "Manager"))
	setIfFound(result, "Template", xmlExtract(content, "Template"))
}

// extractODF extracts metadata from OpenDocument Format files (.odt, .ods, .odp).
func extractODF(data []byte, result *MetadataResult) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return
	}

	for _, f := range r.File {
		if f.Name == "meta.xml" {
			rc, err := f.Open()
			if err != nil {
				return
			}
			defer rc.Close()

			metaData, err := io.ReadAll(io.LimitReader(rc, 1*1024*1024))
			if err != nil {
				return
			}

			content := string(metaData)
			setIfFound(result, "Creator", xmlExtract(content, "meta:initial-creator"))
			setIfFound(result, "Title", xmlExtract(content, "dc:title"))
			setIfFound(result, "Subject", xmlExtract(content, "dc:subject"))
			setIfFound(result, "Description", xmlExtract(content, "dc:description"))
			setIfFound(result, "Generator", xmlExtract(content, "meta:generator"))
			setIfFound(result, "CreationDate", xmlExtract(content, "meta:creation-date"))
			setIfFound(result, "Date", xmlExtract(content, "dc:date"))
			setIfFound(result, "Language", xmlExtract(content, "dc:language"))
			return
		}
	}
}

// extractSVG extracts metadata from SVG files.
func extractSVG(data []byte, result *MetadataResult) {
	content := string(data)
	setIfFound(result, "Title", xmlExtract(content, "title"))
	setIfFound(result, "Description", xmlExtract(content, "desc"))
	setIfFound(result, "Creator", xmlExtract(content, "dc:creator"))
	setIfFound(result, "Publisher", xmlExtract(content, "dc:publisher"))
	setIfFound(result, "Rights", xmlExtract(content, "dc:rights"))
	setIfFound(result, "Date", xmlExtract(content, "dc:date"))

	// Look for Inkscape/Illustrator metadata
	setIfFound(result, "Generator", xmlExtract(content, "rdf:about"))

	// Check for XML comments that might contain tool info
	if idx := strings.Index(content, "<!-- Created with "); idx != -1 {
		end := strings.Index(content[idx:], "-->")
		if end > 0 {
			val := content[idx+18 : idx+end]
			val = strings.TrimSpace(val)
			if val != "" {
				result.Fields["Generator"] = val
			}
		}
	}
	if idx := strings.Index(content, "<!-- Generator: "); idx != -1 {
		end := strings.Index(content[idx:], "-->")
		if end > 0 {
			val := content[idx+16 : idx+end]
			val = strings.TrimSpace(val)
			if val != "" {
				result.Fields["Generator"] = val
			}
		}
	}
}

// extractMP3 extracts ID3 tag metadata from MP3 files.
func extractMP3(data []byte, result *MetadataResult) {
	if len(data) < 10 {
		return
	}

	// Check for ID3v2 header
	if string(data[:3]) == "ID3" {
		extractID3v2(data, result)
		return
	}

	// Check for ID3v1 at the end (last 128 bytes)
	if len(data) >= 128 {
		tail := data[len(data)-128:]
		if string(tail[:3]) == "TAG" {
			setIfFound(result, "Title", strings.TrimRight(string(tail[3:33]), "\x00 "))
			setIfFound(result, "Artist", strings.TrimRight(string(tail[33:63]), "\x00 "))
			setIfFound(result, "Album", strings.TrimRight(string(tail[63:93]), "\x00 "))
			setIfFound(result, "Year", strings.TrimRight(string(tail[93:97]), "\x00 "))
			setIfFound(result, "Comment", strings.TrimRight(string(tail[97:127]), "\x00 "))
		}
	}
}

func extractID3v2(data []byte, result *MetadataResult) {
	if len(data) < 10 {
		return
	}

	// Parse header
	// version := data[3]
	// revision := data[4]
	// flags := data[5]

	// Calculate tag size (syncsafe integer)
	size := int(data[6])<<21 | int(data[7])<<14 | int(data[8])<<7 | int(data[9])
	if size <= 0 || size+10 > len(data) {
		return
	}

	offset := 10
	end := offset + size

	// Frame map for common ID3v2.3/2.4 frames
	frameNames := map[string]string{
		"TIT2": "Title",
		"TPE1": "Artist",
		"TALB": "Album",
		"TDRC": "Year",
		"TYER": "Year",
		"COMM": "Comment",
		"TCON": "Genre",
		"TENC": "EncodedBy",
		"TSSE": "EncoderSettings",
		"TXXX": "UserDefined",
		"TCOP": "Copyright",
		"TPUB": "Publisher",
		"TPE2": "AlbumArtist",
		"TCOM": "Composer",
	}

	for offset+10 <= end {
		frameID := string(data[offset : offset+4])
		if frameID[0] == 0 {
			break // padding
		}

		frameSize := int(binary.BigEndian.Uint32(data[offset+4 : offset+8]))
		// Skip flags (2 bytes)
		offset += 10

		if frameSize <= 0 || offset+frameSize > end {
			break
		}

		if name, ok := frameNames[frameID]; ok {
			frameData := data[offset : offset+frameSize]
			val := decodeID3Text(frameData)
			setIfFound(result, name, val)
		}

		offset += frameSize
	}
}

func decodeID3Text(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	encoding := data[0]
	text := data[1:]

	switch encoding {
	case 0: // ISO-8859-1
		return strings.TrimRight(string(text), "\x00")
	case 1: // UTF-16 with BOM
		if len(text) >= 2 {
			// Skip BOM
			if text[0] == 0xFF && text[1] == 0xFE {
				text = text[2:]
			} else if text[0] == 0xFE && text[1] == 0xFF {
				text = text[2:]
			}
		}
		var result []byte
		for i := 0; i+1 < len(text); i += 2 {
			ch := rune(text[i]) | rune(text[i+1])<<8
			if ch == 0 {
				break
			}
			if ch < 128 {
				result = append(result, byte(ch))
			}
		}
		return string(result)
	case 3: // UTF-8
		return strings.TrimRight(string(text), "\x00")
	default:
		return strings.TrimRight(string(text), "\x00")
	}
}

// extractOLE attempts to extract metadata from legacy Office files (.doc, .xls, .ppt).
// OLE2 compound documents store metadata in property set streams.
func extractOLE(data []byte, result *MetadataResult) {
	// Check OLE2 magic number
	if len(data) < 512 || !bytes.Equal(data[:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}) {
		return
	}

	// Extract UTF-16LE strings from the binary — OLE stores metadata as UTF-16LE
	// Search for DocumentSummaryInformation and SummaryInformation property sets
	extractOLEStrings(data, result)
}

// extractOLEStrings scans OLE binary for readable UTF-16LE metadata strings.
func extractOLEStrings(data []byte, result *MetadataResult) {
	// Known property markers in SummaryInformation stream
	// We look for UTF-16LE encoded strings following known patterns
	content := string(data)

	// Application name
	appMarkers := []string{"Microsoft Word", "Microsoft Excel", "Microsoft PowerPoint", "Microsoft Office"}
	for _, marker := range appMarkers {
		if idx := strings.Index(content, marker); idx != -1 {
			end := idx + len(marker)
			for end < len(content) && end < idx+100 && data[end] != 0 {
				end++
			}
			setIfFound(result, "Application", content[idx:end])
			break
		}
	}

	// Try to find UTF-16LE encoded strings
	// Scan for runs of UTF-16LE text (alternating printable byte + 0x00)
	utf16Strings := extractUTF16LEStrings(data, 8)

	// Heuristic: look for author-like and software-like strings
	for _, s := range utf16Strings {
		lower := strings.ToLower(s)

		// Application/software
		for _, marker := range appMarkers {
			if strings.Contains(lower, strings.ToLower(marker)) {
				setIfFound(result, "Application", s)
			}
		}

		// Windows username pattern in paths
		if windowsPath.MatchString(s) {
			setIfFound(result, "InternalPath", s)
		}
	}
}

// extractUTF16LEStrings finds UTF-16LE encoded strings in binary data.
func extractUTF16LEStrings(data []byte, minLen int) []string {
	var strings []string
	var current []uint16

	for i := 0; i+1 < len(data); i += 2 {
		cp := uint16(data[i]) | uint16(data[i+1])<<8
		if cp >= 0x20 && cp < 0x7F {
			current = append(current, cp)
		} else {
			if len(current) >= minLen {
				strings = append(strings, string(utf16.Decode(current)))
			}
			current = current[:0]
		}
	}
	if len(current) >= minLen {
		strings = append(strings, string(utf16.Decode(current)))
	}
	return strings
}

// extractXMP searches for XMP metadata blocks in raw data.
// XMP can appear in JPEG, PNG, PDF, TIFF, and many other formats.
func extractXMP(data []byte, result *MetadataResult) {
	content := string(data)

	// Find XMP block boundaries
	var xmpBlock string
	if idx := strings.Index(content, "<x:xmpmeta"); idx != -1 {
		end := strings.Index(content[idx:], "</x:xmpmeta>")
		if end > 0 {
			xmpBlock = content[idx : idx+end+12]
		}
	} else if idx := strings.Index(content, "<rdf:RDF"); idx != -1 {
		end := strings.Index(content[idx:], "</rdf:RDF>")
		if end > 0 {
			xmpBlock = content[idx : idx+end+10]
		}
	}

	if xmpBlock == "" {
		return
	}

	// Extract XMP fields — only set if not already present from other extractors
	xmpFields := []struct {
		tag   string
		field string
	}{
		{"dc:creator", "Creator"},
		{"dc:title", "Title"},
		{"dc:description", "Description"},
		{"dc:subject", "Keywords"},
		{"dc:rights", "Copyright"},
		{"xmp:CreatorTool", "Creator"},
		{"xmp:CreateDate", "CreationDate"},
		{"xmp:ModifyDate", "ModDate"},
		{"xmp:MetadataDate", "MetadataDate"},
		{"pdf:Producer", "Producer"},
		{"pdf:Keywords", "Keywords"},
		{"photoshop:AuthorsPosition", "AuthorPosition"},
		{"photoshop:CaptionWriter", "CaptionWriter"},
		{"photoshop:City", "City"},
		{"photoshop:State", "State"},
		{"photoshop:Country", "Country"},
		{"Iptc4xmpCore:CreatorContactInfo", "CreatorContact"},
		{"tiff:Make", "Make"},
		{"tiff:Model", "Model"},
		{"tiff:Software", "Software"},
		{"exif:LensModel", "LensModel"},
	}

	for _, f := range xmpFields {
		if _, exists := result.Fields[f.field]; exists {
			continue
		}
		// Try rdf:li extraction first (gives clean inner text)
		val := xmpExtractLi(xmpBlock, f.tag)
		if val == "" {
			val = xmlExtract(xmpBlock, f.tag)
			// Strip any remaining XML tags from the value
			val = stripXMLTags(val)
		}
		setIfFound(result, f.field, val)
	}
}

// xmpExtractLi handles XMP fields wrapped in <rdf:Seq><rdf:li> or <rdf:Alt><rdf:li>.
func xmpExtractLi(content, tag string) string {
	open := "<" + tag
	idx := strings.Index(content, open)
	if idx == -1 {
		return ""
	}
	closeTag := "</" + tag + ">"
	end := strings.Index(content[idx:], closeTag)
	if end == -1 {
		return ""
	}
	block := content[idx : idx+end]
	val := xmlExtract(block, "rdf:li")
	return stripXMLTags(val)
}

// extractGIF extracts comment extensions from GIF files.
func extractGIF(data []byte, result *MetadataResult) {
	if len(data) < 6 {
		return
	}
	sig := string(data[:6])
	if sig != "GIF87a" && sig != "GIF89a" {
		return
	}

	// Skip header + logical screen descriptor
	offset := 6
	if offset+7 > len(data) {
		return
	}

	// Check for global color table
	flags := data[offset+4]
	hasGCT := flags&0x80 != 0
	gctSize := 0
	if hasGCT {
		gctSize = 3 * (1 << ((flags & 0x07) + 1))
	}
	offset += 7 + gctSize

	// Scan for comment extension blocks (0x21 0xFE)
	for offset+2 < len(data) {
		if data[offset] == 0x3B { // trailer
			break
		}
		if data[offset] == 0x21 { // extension
			if offset+1 < len(data) && data[offset+1] == 0xFE { // comment
				offset += 2
				var comment []byte
				for offset < len(data) {
					blockSize := int(data[offset])
					offset++
					if blockSize == 0 {
						break
					}
					if offset+blockSize > len(data) {
						break
					}
					comment = append(comment, data[offset:offset+blockSize]...)
					offset += blockSize
				}
				if len(comment) > 0 {
					setIfFound(result, "Comment", string(comment))
				}
				continue
			}
			// Skip other extensions
			offset += 2
			for offset < len(data) {
				blockSize := int(data[offset])
				offset++
				if blockSize == 0 {
					break
				}
				offset += blockSize
			}
			continue
		}
		if data[offset] == 0x2C { // image descriptor
			offset += 10
			if offset > len(data) {
				break
			}
			localFlags := data[offset-1]
			hasLCT := localFlags&0x80 != 0
			if hasLCT {
				lctSize := 3 * (1 << ((localFlags & 0x07) + 1))
				offset += lctSize
			}
			offset++ // LZW min code size
			// Skip image data sub-blocks
			for offset < len(data) {
				blockSize := int(data[offset])
				offset++
				if blockSize == 0 {
					break
				}
				offset += blockSize
			}
			continue
		}
		offset++
	}
}

// extractWebP extracts EXIF metadata from WebP files (RIFF container).
func extractWebP(data []byte, result *MetadataResult) {
	if len(data) < 12 {
		return
	}
	if string(data[:4]) != "RIFF" || string(data[8:12]) != "WEBP" {
		return
	}

	offset := 12
	for offset+8 <= len(data) {
		chunkID := string(data[offset : offset+4])
		chunkSize := int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		offset += 8

		if chunkSize < 0 || offset+chunkSize > len(data) {
			break
		}

		switch chunkID {
		case "EXIF":
			chunkData := data[offset : offset+chunkSize]
			// WebP EXIF may start with "Exif\x00\x00" prefix
			if len(chunkData) > 6 && string(chunkData[:4]) == "Exif" {
				chunkData = chunkData[6:]
			}
			extractEXIF(chunkData, result)
		case "XMP ":
			extractXMP(data[offset:offset+chunkSize], result)
		}

		// Chunks are padded to even size
		if chunkSize%2 != 0 {
			chunkSize++
		}
		offset += chunkSize
	}
}

// cleanFields strips non-printable/control characters from all extracted field values.
func cleanFields(result *MetadataResult) {
	for k, v := range result.Fields {
		cleaned := cleanString(v)
		if cleaned == "" {
			delete(result.Fields, k)
		} else {
			result.Fields[k] = cleaned
		}
	}
}

// cleanString removes non-printable characters, decodes XML entities, and trims whitespace.
func cleanString(s string) string {
	// Decode common XML/HTML entities
	s = strings.ReplaceAll(s, "&#39;", "'")
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&quot;", "\"")
	s = strings.ReplaceAll(s, "&apos;", "'")

	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\t' || r == '\n' {
			b.WriteRune(' ')
		} else if r >= ' ' && utf8.ValidRune(r) && r != 0xFFFD {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

func xmlExtract(content, tag string) string {
	open := "<" + tag
	closeTag := "</" + tag + ">"

	idx := strings.Index(content, open)
	if idx == -1 {
		return ""
	}

	// Find the end of the opening tag
	tagEnd := strings.IndexByte(content[idx:], '>')
	if tagEnd == -1 {
		return ""
	}
	start := idx + tagEnd + 1

	// Check for self-closing tag
	if content[idx+tagEnd-1] == '/' {
		return ""
	}

	end := strings.Index(content[start:], closeTag)
	if end == -1 {
		return ""
	}

	return strings.TrimSpace(content[start : start+end])
}

// stripXMLTags removes XML/HTML tags from a string.
func stripXMLTags(s string) string {
	var b strings.Builder
	inTag := false
	for _, r := range s {
		if r == '<' {
			inTag = true
			continue
		}
		if r == '>' {
			inTag = false
			continue
		}
		if !inTag {
			b.WriteRune(r)
		}
	}
	// Collapse whitespace
	result := strings.Join(strings.Fields(b.String()), " ")
	return strings.TrimSpace(result)
}

func setIfFound(result *MetadataResult, key, val string) {
	val = strings.TrimSpace(val)
	if val != "" {
		result.Fields[key] = val
	}
}
