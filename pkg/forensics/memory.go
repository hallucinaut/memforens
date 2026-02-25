// Package forensics provides memory forensics functionality.
package forensics

import (
	"fmt"
	"regexp"
	"strings"
)

// MemoryRegion represents a region of memory.
type MemoryRegion struct {
	StartAddr uint64
	EndAddr   uint64
	Size      uint64
	Permissions string
	Mapping   string
}

// MemoryDump represents a memory dump analysis result.
type MemoryDump struct {
	FilePath     string
	Architecture string
	OS           string
	Regions      []MemoryRegion
	Processes    []Process
	Secrets      []Secret
	NetworkConns []NetworkConnection
	LoadedModules []Module
	AnalysisTime  string
}

// Process represents a process found in memory.
type Process struct {
	Name       string
	PID        uint32
	PPID       uint32
	State      string
	StartTime  string
	CommandLine string
	EnvVars    []string
}

// Secret represents a potential secret found in memory.
type Secret struct {
	Type       string
	Value      string
	Location   string
	Context    string
	Confidence float64
}

// NetworkConnection represents a network connection.
type NetworkConnection struct {
	LocalAddr   string
	RemoteAddr  string
	State       string
	PID         uint32
	ProcessName string
	Protocol    string
}

// Module represents a loaded module/library.
type Module struct {
	Name    string
	BaseAddr uint64
	Size    uint64
	Path    string
}

// Scanner analyzes memory dumps for various artifacts.
type Scanner struct {
	knownSecrets []SecretPattern
	knownPatterns []Pattern
}

// SecretPattern defines a pattern for secret detection.
type SecretPattern struct {
	Name      string
	Pattern   *regexp.Regexp
	Confidence float64
	Example   string
}

// Pattern defines a generic pattern.
type Pattern struct {
	Name    string
	Pattern *regexp.Regexp
}

// NewScanner creates a new memory scanner with known patterns.
func NewScanner() *Scanner {
	return &Scanner{
		knownSecrets: []SecretPattern{
			{
				Name: "AWS Access Key",
				Pattern: regexp.MustCompile(`(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
				Confidence: 0.95,
				Example:   "AKIAIOSFODNN7EXAMPLE",
			},
			{
				Name: "AWS Secret Key",
				Pattern: regexp.MustCompile(`(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
				Confidence: 0.90,
				Example:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
			{
				Name: "GitHub Token",
				Pattern: regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}`),
				Confidence: 0.95,
				Example:   "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			},
			{
				Name: "Generic API Key",
				Pattern: regexp.MustCompile(`(?i)(api[_-]?key|apikey|api_key)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?`),
				Confidence: 0.70,
				Example:   "api_key=xxxxxxxxxxxxxxxxxxxx",
			},
			{
				Name: "JWT Token",
				Pattern: regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`),
				Confidence: 0.85,
				Example:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
			},
			{
				Name: "Private Key",
				Pattern: regexp.MustCompile(`-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----`),
				Confidence: 1.0,
				Example:   "-----BEGIN RSA PRIVATE KEY-----",
			},
			{
				Name: "Password in Memory",
				Pattern: regexp.MustCompile(`(?i)(password|passwd|pwd|pass)\s*[=:]\s*['"]?([^\s'"']{4,})['"]?`),
				Confidence: 0.60,
				Example:   "password=secret123",
			},
		},
		knownPatterns: []Pattern{
			{
				Name: "URL Pattern",
				Pattern: regexp.MustCompile(`https?://[^\s"'<>]+`),
			},
			{
				Name: "Email Pattern",
				Pattern: regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
			},
			{
				Name: "IP Address",
				Pattern: regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
			},
		},
	}
}

// ScanMemory scans memory data for secrets and artifacts.
func (s *Scanner) ScanMemory(data []byte) ([]Secret, error) {
	var secrets []Secret
	foundSecrets := make(map[string]bool)

	for _, pattern := range s.knownSecrets {
		matches := pattern.Pattern.FindAllSubmatch(data, -1)
		for _, match := range matches {
			if len(match) > 1 {
				secretValue := string(match[1])
				key := fmt.Sprintf("%s:%s", pattern.Name, secretValue)
				
				if !foundSecrets[key] {
					foundSecrets[key] = true
					secrets = append(secrets, Secret{
						Type:       pattern.Name,
						Value:      secretValue,
						Confidence: pattern.Confidence,
					})
				}
			}
		}
	}

	return secrets, nil
}

// ScanForPatterns scans memory data for known patterns.
func (s *Scanner) ScanForPatterns(data []byte) []string {
	var matches []string

	for _, pattern := range s.knownPatterns {
		matches = append(matches, pattern.Pattern.FindAllString(string(data), -1)...)
	}

	return matches
}

// ExtractStrings extracts printable strings from memory data.
func ExtractStrings(data []byte, minLen int) []string {
	var strings []string
	var current []byte

	for _, b := range data {
		if b >= 0x20 && b <= 0x7e {
			current = append(current, b)
		} else {
			if len(current) >= minLen {
				strings = append(strings, string(current))
			}
			current = nil
		}
	}

	if len(current) >= minLen {
		strings = append(strings, string(current))
	}

	return strings
}

// ParseMemoryRegions parses memory region information from proc/self/maps format.
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

		// Parse address range
		addrRange := strings.Split(parts[0], "-")
		if len(addrRange) != 2 {
			continue
		}

		startAddr, _ := parseHex(addrRange[0])
		endAddr, _ := parseHex(addrRange[1])

		region := MemoryRegion{
			StartAddr:   startAddr,
			EndAddr:     endAddr,
			Size:        endAddr - startAddr,
			Permissions: parts[1],
			Mapping:     parts[5],
		}

		regions = append(regions, region)
	}

	return regions
}

// ParseProcessInfo parses process information from proc format.
func ParseProcessInfo(content string) []Process {
	var processes []Process
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		if i == 0 {
			continue // Skip header
		}
		
		parts := strings.Fields(line)
		if len(parts) < 11 {
			continue
		}

		pid, _ := parseUint(parts[1])
		ppid, _ := parseUint(parts[3])
		startTime, _ := parseUint(parts[20])

		process := Process{
			Name:    parts[0],
			PID:     uint32(pid),
			PPID:    uint32(ppid),
			State:   parts[2],
			StartTime: fmt.Sprintf("%d", startTime),
		}

		processes = append(processes, process)
	}

	return processes
}

// parseHex parses a hex string to uint64.
func parseHex(s string) (uint64, error) {
	var result uint64
	fmt.Sscanf(s, "%x", &result)
	return result, nil
}

// parseUint parses a string to uint.
func parseUint(s string) (uint64, error) {
	var result uint64
	fmt.Sscanf(s, "%d", &result)
	return result, nil
}

// ReadMemoryFile reads memory dump file content.
func ReadMemoryFile(filepath string) ([]byte, error) {
	// This is a placeholder - in production would read actual memory dump
	return []byte{}, fmt.Errorf("memory reading not implemented in demo")
}

// ScanFile scans a file for secrets and artifacts.
func (s *Scanner) ScanFile(filepath string) (*MemoryDump, error) {
	data, err := ReadMemoryFile(filepath)
	if err != nil {
		return nil, err
	}

	dump := &MemoryDump{
		FilePath:     filepath,
		Architecture: "x86_64",
		OS:           "Linux",
		AnalysisTime: "2024-02-25T00:00:00Z",
	}

	// Extract strings
	extractedStrings := ExtractStrings(data, 8)
	dump.NetworkConns = make([]NetworkConnection, 0)
	dump.Secrets = make([]Secret, 0)

	// Scan for secrets
	secrets, err := s.ScanMemory(data)
	if err != nil {
		return nil, err
	}
	dump.Secrets = secrets

	// Find URLs and IPs
	patternMatches := s.ScanForPatterns(data)
	for _, match := range patternMatches {
		if strings.HasPrefix(match, "http") {
			// Would add to network connections
		}
	}
	_ = extractedStrings

	return dump, nil
}

// GetSecrets returns all detected secrets with confidence filtering.
func (s *Scanner) GetSecrets(secrets []Secret, minConfidence float64) []Secret {
	var filtered []Secret
	for _, secret := range secrets {
		if secret.Confidence >= minConfidence {
			filtered = append(filtered, secret)
		}
	}
	return filtered
}

// GetSecretsByType returns secrets filtered by type.
func (s *Scanner) GetSecretsByType(secrets []Secret, secretType string) []Secret {
	var filtered []Secret
	for _, secret := range secrets {
		if secret.Type == secretType {
			filtered = append(filtered, secret)
		}
	}
	return filtered
}

// ExportSecrets exports secrets to YAML format.
func ExportSecrets(secrets []Secret) (string, error) {
	// Simplified export
	var sb strings.Builder
	for _, secret := range secrets {
		sb.WriteString(fmt.Sprintf("- type: %s\n", secret.Type))
		sb.WriteString(fmt.Sprintf("  value: %s\n", secret.Value))
		sb.WriteString(fmt.Sprintf("  confidence: %.2f\n", secret.Confidence))
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

// AnalyzeMemory analyzes memory dump and returns comprehensive report.
func AnalyzeMemory(data []byte) *MemoryDump {
	scanner := NewScanner()

	dump := &MemoryDump{
		Architecture: "x86_64",
		OS:           "Linux",
		AnalysisTime: "2024-02-25T00:00:00Z",
	}

	// Extract strings
	_ = ExtractStrings(data, 4)
	dump.NetworkConns = make([]NetworkConnection, 0)
	dump.Secrets = make([]Secret, 0)

	// Scan for secrets
	secrets, _ := scanner.ScanMemory(data)
	dump.Secrets = secrets

	// Count findings
	dump.Processes = make([]Process, 0)
	dump.LoadedModules = make([]Module, 0)

	return dump
}