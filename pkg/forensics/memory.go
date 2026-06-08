// Package forensics provides memory forensics functionality for detecting
// secrets, credentials, and artifacts in binary data.
package forensics

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

const contextWindow = 50 // bytes of context to capture around matches

// MemoryRegion represents a region of memory from /proc/self/maps format.
type MemoryRegion struct {
	StartAddr   uint64
	EndAddr     uint64
	Size        uint64
	Permissions string
	Mapping     string
}

// Process represents a process entry from /proc/pid/stat format.
type Process struct {
	Name        string
	PID         uint32
	PPID        uint32
	State       string
	StartTime   uint64
	CommandLine string
}

// Secret represents a detected secret with metadata.
type Secret struct {
	Type       string
	Value      string
	Location   string
	Context    string
	Confidence float64
}

// NetworkConnection represents a network connection entry from /proc/net/tcp format.
type NetworkConnection struct {
	LocalAddr  string
	RemoteAddr string
	State      string
	PID        uint32
	Protocol   string
}

// Module represents a loaded shared library.
type Module struct {
	Name     string
	BaseAddr uint64
	Size     uint64
	Path     string
}

// PatternMatch represents a single match from pattern scanning.
type PatternMatch struct {
	Name  string
	Value string
	Pos   int
}

// SecretPattern defines a regex pattern for secret detection.
type SecretPattern struct {
	Name       string
	Pattern    *regexp.Regexp
	Confidence float64
}

// GenericPattern defines a regex pattern for general artifact detection.
type GenericPattern struct {
	Name  string
	Pattern *regexp.Regexp
}

// Scanner analyzes binary data for secrets and artifacts.
type Scanner struct {
	secretPatterns    []SecretPattern
	genericPatterns   []GenericPattern
}

// NewScanner creates a new Scanner pre-configured with known secret patterns.
func NewScanner() *Scanner {
	return &Scanner{
		secretPatterns: []SecretPattern{
			{
				Name:       "AWS Access Key",
				Pattern:    regexp.MustCompile(`(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
				Confidence: 0.95,
			},
			{
				Name:       "AWS Secret Key",
				Pattern:    regexp.MustCompile(`(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
				Confidence: 0.90,
			},
			{
				Name:       "GitHub Token",
				Pattern:    regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}`),
				Confidence: 0.95,
			},
			{
				Name:       "Generic API Key",
				Pattern:    regexp.MustCompile(`(?i)(api[_\-]?key|apikey|api_key)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?`),
				Confidence: 0.70,
			},
			{
				Name:       "JWT Token",
				Pattern:    regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
				Confidence: 0.85,
			},
			{
				Name:       "Private Key",
				Pattern:    regexp.MustCompile(`-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----`),
				Confidence: 1.00,
			},
			{
				Name:       "Password Assignment",
				Pattern:    regexp.MustCompile(`(?i)(password|passwd|pwd|pass)\s*[=:]\s*['"]?([^\s'"&;]{4,})['"]?`),
				Confidence: 0.60,
			},
		},
		genericPatterns: []GenericPattern{
			{
				Name:      "URL",
				Pattern:   regexp.MustCompile(`https?://[^\s"'<>]+`),
			},
			{
				Name:      "Email",
				Pattern:   regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
			},
			{
				Name:      "IPv4 Address",
				Pattern:   regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
			},
		},
	}
}

// ScanMemory scans binary data for secrets and returns deduplicated results.
func (s *Scanner) ScanMemory(data []byte) ([]Secret, error) {
	var secrets []Secret
	found := make(map[string]bool)

	for _, p := range s.secretPatterns {
		matches := p.Pattern.FindAllSubmatchIndex(data, -1)
		if matches == nil {
			continue
		}
		for _, match := range matches {
			value := string(data[match[0]:match[1]])
			key := p.Name + ":" + value
			if found[key] {
				continue
			}
			found[key] = true

			context := extractContext(data, match[0], match[1])
			location := byteOffsetToHex(match[0])

			secrets = append(secrets, Secret{
				Type:       p.Name,
				Value:      value,
				Location:   location,
				Context:    context,
				Confidence: p.Confidence,
			})
		}
	}

	return secrets, nil
}

// ScanForPatterns scans binary data for generic artifacts (URLs, emails, IPs).
func (s *Scanner) ScanForPatterns(data []byte) []PatternMatch {
	var matches []PatternMatch

	for _, p := range s.genericPatterns {
		submatches := p.Pattern.FindAllSubmatchIndex(data, -1)
		if submatches == nil {
			continue
		}
		for _, m := range submatches {
			matches = append(matches, PatternMatch{
				Name:  p.Name,
				Value: string(data[m[0]:m[1]]),
				Pos:   m[0],
			})
		}
	}

	return matches
}

// ExtractStrings extracts printable ASCII strings of at least minLen length.
func ExtractStrings(data []byte, minLen int) []string {
	if minLen < 1 {
		minLen = 4
	}
	var result []string
	var current strings.Builder

	for _, b := range data {
		if b >= 0x20 && b <= 0x7e {
			current.WriteByte(b)
		} else {
			if current.Len() >= minLen {
				result = append(result, current.String())
			}
			current.Reset()
		}
	}

	if current.Len() >= minLen {
		result = append(result, current.String())
	}

	return result
}

// ReadMemoryFile reads a file from disk and returns its contents.
func ReadMemoryFile(filepath string) ([]byte, error) {
	return os.ReadFile(filepath)
}

// ParseMemoryRegions parses /proc/self/maps format data into MemoryRegion structs.
func ParseMemoryRegions(content string) []MemoryRegion {
	var regions []MemoryRegion
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 6 {
			continue
		}

		addrParts := strings.Split(parts[0], "-")
		if len(addrParts) != 2 {
			continue
		}

		startAddr, err := parseHex(addrParts[0])
		if err != nil {
			continue
		}
		endAddr, err := parseHex(addrParts[1])
		if err != nil {
			continue
		}

		regions = append(regions, MemoryRegion{
			StartAddr:   startAddr,
			EndAddr:     endAddr,
			Size:        endAddr - startAddr,
			Permissions: parts[1],
			Mapping:     parts[5],
		})
	}

	return regions
}

// ParseProcessInfo parses /proc/pid/stat format data into Process structs.
func ParseProcessInfo(content string) []Process {
	var processes []Process
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// /proc/pid/stat format: pid (comm) state ppid ...
		// comm is enclosed in parentheses and may contain spaces, so find the last ')'
		closeParen := strings.LastIndex(line, ")")
		if closeParen == -1 {
			continue
		}

		beforeComm := line[:strings.Index(line, "(")]
		afterComm := line[closeParen+2:] // skip ") "

		parts := strings.Fields(beforeComm)
		if len(parts) < 1 {
			continue
		}

		pid, err := parseUint(parts[0])
		if err != nil {
			continue
		}

		ppidParts := strings.Fields(afterComm)
		var ppid uint64
		if len(ppidParts) >= 2 {
			ppid, _ = parseUint(ppidParts[1])
		}

		state := ""
		if len(ppidParts) > 0 {
			state = ppidParts[0]
		}

		var startTime uint64
		if len(ppidParts) >= 20 {
			startTime, _ = parseUint(ppidParts[19])
		}

		process := Process{
			Name:      line[strings.Index(line, "(")+1 : closeParen],
			PID:       uint32(pid),
			PPID:      uint32(ppid),
			State:     state,
			StartTime: startTime,
		}

		processes = append(processes, process)
	}

	return processes
}

// byteOffsetToHex converts a byte offset to a hex string.
func byteOffsetToHex(offset int) string {
	return "0x" + fmt.Sprintf("%08x", offset)
}

// extractContext returns the surrounding bytes around a match range as a string.
func extractContext(data []byte, start, end int) string {
	ctxStart := 0
	if start > contextWindow {
		ctxStart = start - contextWindow
	}
	ctxEnd := len(data)
	if end+contextWindow < ctxEnd {
		ctxEnd = end + contextWindow
	}

	return string(data[ctxStart:ctxEnd])
}

// parseHex converts a hex string to uint64.
func parseHex(s string) (uint64, error) {
	var result uint64
	n, err := fmt.Sscanf(s, "%x", &result)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("invalid hex value: %s", s)
	}
	return result, nil
}

// parseUint converts a decimal string to uint64.
func parseUint(s string) (uint64, error) {
	var result uint64
	n, err := fmt.Sscanf(s, "%d", &result)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("invalid integer value: %s", s)
	}
	return result, nil
}

// FilterSecretsByConfidence returns secrets with confidence >= minConfidence.
func FilterSecretsByConfidence(secrets []Secret, minConfidence float64) []Secret {
	var filtered []Secret
	for _, s := range secrets {
		if s.Confidence >= minConfidence {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

// FilterSecretsByType returns secrets matching the given type.
func FilterSecretsByType(secrets []Secret, secretType string) []Secret {
	var filtered []Secret
	for _, s := range secrets {
		if s.Type == secretType {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

// AnalyzeMemory performs a full analysis of binary data and returns a report.
func AnalyzeMemory(data []byte) *MemoryDump {
	scanner := NewScanner()

	secrets, _ := scanner.ScanMemory(data)
	patternMatches := scanner.ScanForPatterns(data)

	// Count pattern match types
	urlCount := 0
	emailCount := 0
	ipCount := 0
	for _, m := range patternMatches {
		switch m.Name {
		case "URL":
			urlCount++
		case "Email":
			emailCount++
		case "IPv4 Address":
			ipCount++
		}
	}

	return &MemoryDump{
		DataSize:    len(data),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Secrets:     secrets,
		URLCount:    urlCount,
		EmailCount:  emailCount,
		IPCount:     ipCount,
	}
}

// MemoryDump holds the results of a memory analysis.
type MemoryDump struct {
	DataSize   int
	Timestamp  string
	Secrets    []Secret
	URLCount   int
	EmailCount int
	IPCount    int
}
