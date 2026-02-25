package forensics

import (
	"regexp"
	"testing"
)

func TestNewScanner(t *testing.T) {
	scanner := NewScanner()
	
	if scanner == nil {
		t.Error("Expected non-nil scanner")
	}
	
	if len(scanner.knownSecrets) == 0 {
		t.Error("Expected known secrets to be initialized")
	}
}

func TestScanMemory_AWSKey(t *testing.T) {
	scanner := NewScanner()
	
	data := []byte("AKIAIOSFODNN7EXAMPLE is my AWS key")
	
	secrets, err := scanner.ScanMemory(data)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	
	found := false
	for _, secret := range secrets {
		if secret.Type == "AWS Access Key" {
			found = true
			if secret.Confidence != 0.95 {
				t.Errorf("Expected confidence 0.95, got %.2f", secret.Confidence)
			}
		}
	}
	
	if !found {
		t.Error("Expected to find AWS Access Key secret")
	}
}

func TestScanMemory_JWT(t *testing.T) {
	scanner := NewScanner()
	
	jwtToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	data := []byte("token=" + jwtToken)
	
	secrets, err := scanner.ScanMemory(data)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	
	found := false
	for _, secret := range secrets {
		if secret.Type == "JWT Token" {
			found = true
			if len(secret.Value) < 10 {
				t.Errorf("Expected JWT value to be long enough")
			}
		}
	}
	
	if !found {
		t.Error("Expected to find JWT Token secret")
	}
}

func TestScanMemory_PrivateKey(t *testing.T) {
	scanner := NewScanner()
	
	data := []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...")
	
	secrets, err := scanner.ScanMemory(data)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	
	found := false
	for _, secret := range secrets {
		if secret.Type == "Private Key" {
			found = true
			if secret.Confidence != 1.0 {
				t.Errorf("Expected confidence 1.0, got %.2f", secret.Confidence)
			}
		}
	}
	
	if !found {
		t.Error("Expected to find Private Key secret")
	}
}

func TestExtractStrings(t *testing.T) {
	data := []byte("Hello\x00World\x00Test123\x00ABC")
	
	strings := ExtractStrings(data, 3)
	
	if len(strings) != 3 {
		t.Errorf("Expected 3 strings, got %d", len(strings))
	}
	
	expected := []string{"Hello", "World", "Test123"}
	for i, s := range strings {
		if s != expected[i] {
			t.Errorf("Expected '%s', got '%s'", expected[i], s)
		}
	}
}

func TestExtractStrings_MinLength(t *testing.T) {
	data := []byte("Hi\x00World\x00ABC")
	
	strings := ExtractStrings(data, 5)
	
	if len(strings) != 1 {
		t.Errorf("Expected 1 string (World), got %d", len(strings))
	}
	
	if strings[0] != "World" {
		t.Errorf("Expected 'World', got '%s'", strings[0])
	}
}

func TestParseMemoryRegions(t *testing.T) {
	content := `00400000-00454000 r-xp 00000000 08:0a 123456    /bin/cat
00653000-00654000 r--p 00053000 08:0a 123456    /bin/cat
7fff12340000-7fff12361000 rw-p 00000000 00:00 0`
	
	regions := ParseMemoryRegions(content)
	
	if len(regions) != 3 {
		t.Errorf("Expected 3 regions, got %d", len(regions))
	}
	
	if regions[0].Permissions != "r-xp" {
		t.Errorf("Expected 'r-xp', got '%s'", regions[0].Permissions)
	}
	
	if regions[0].Mapping != "/bin/cat" {
		t.Errorf("Expected '/bin/cat', got '%s'", regions[0].Mapping)
	}
}

func TestGetSecretsByType(t *testing.T) {
	scanner := NewScanner()
	
	secrets := []Secret{
		{Type: "AWS Access Key", Value: "key1", Confidence: 0.95},
		{Type: "AWS Access Key", Value: "key2", Confidence: 0.90},
		{Type: "JWT Token", Value: "token1", Confidence: 0.85},
	}
	
	filtered := scanner.GetSecretsByType(secrets, "AWS Access Key")
	
	if len(filtered) != 2 {
		t.Errorf("Expected 2 AWS keys, got %d", len(filtered))
	}
	
	filtered = scanner.GetSecretsByType(secrets, "JWT Token")
	if len(filtered) != 1 {
		t.Errorf("Expected 1 JWT token, got %d", len(filtered))
	}
}

func TestGetSecretsByConfidence(t *testing.T) {
	scanner := NewScanner()
	
	secrets := []Secret{
		{Type: "AWS Access Key", Value: "key1", Confidence: 0.95},
		{Type: "AWS Access Key", Value: "key2", Confidence: 0.90},
		{Type: "JWT Token", Value: "token1", Confidence: 0.85},
		{Type: "Password", Value: "pass1", Confidence: 0.60},
	}
	
	filtered := scanner.GetSecrets(secrets, 0.90)
	
	if len(filtered) != 2 {
		t.Errorf("Expected 2 secrets with confidence >= 0.90, got %d", len(filtered))
	}
}

func TestPatternMatching(t *testing.T) {
	scanner := NewScanner()
	
	data := []byte("Contact: user@example.com, IP: 192.168.1.1, URL: https://example.com")
	
	matches := scanner.ScanForPatterns(data)
	
	// Should find at least email and URL
	emailFound := false
	urlFound := false
	
	for _, match := range matches {
		if match == "user@example.com" {
			emailFound = true
		}
		if match == "https://example.com" {
			urlFound = true
		}
	}
	
	if !emailFound {
		t.Error("Expected to find email address")
	}
	if !urlFound {
		t.Error("Expected to find URL")
	}
}

func TestDuplicateSecrets(t *testing.T) {
	scanner := NewScanner()
	
	// Same secret twice
	data := []byte("AKIAIOSFODNN7EXAMPLE and AKIAIOSFODNN7EXAMPLE")
	
	secrets, err := scanner.ScanMemory(data)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	
	// Should deduplicate
	awsKeys := scanner.GetSecretsByType(secrets, "AWS Access Key")
	if len(awsKeys) != 1 {
		t.Errorf("Expected 1 unique AWS key, got %d", len(awsKeys))
	}
}

func TestExtractStrings_Empty(t *testing.T) {
	data := []byte("\x00\x00\x00")
	
	strings := ExtractStrings(data, 4)
	
	if len(strings) != 0 {
		t.Errorf("Expected 0 strings, got %d", len(strings))
	}
}

func TestExtractStrings_Single(t *testing.T) {
	data := []byte("Hello")
	
	strings := ExtractStrings(data, 4)
	
	if len(strings) != 1 || strings[0] != "Hello" {
		t.Errorf("Expected ['Hello'], got %v", strings)
	}
}

func TestPattern_PatternField(t *testing.T) {
	pattern := Pattern{
		Name:    "Test",
		Pattern: regexp.MustCompile(`test`),
	}
	
	if pattern.Name != "Test" {
		t.Errorf("Expected name 'Test', got '%s'", pattern.Name)
	}
	
	if pattern.Pattern == nil {
		t.Error("Expected pattern to be non-nil")
	}
}

func TestSecretPattern_Confidence(t *testing.T) {
	pattern := SecretPattern{
		Name:      "Test",
		Pattern:   regexp.MustCompile(`test`),
		Confidence: 0.8,
		Example:   "example",
	}
	
	if pattern.Confidence != 0.8 {
		t.Errorf("Expected confidence 0.8, got %f", pattern.Confidence)
	}
}