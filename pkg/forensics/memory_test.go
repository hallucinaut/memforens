package forensics

import (
	"testing"
)

func TestNewScanner(t *testing.T) {
	scanner := NewScanner()

	if scanner == nil {
		t.Error("expected non-nil scanner")
	}

	if len(scanner.secretPatterns) == 0 {
		t.Error("expected secret patterns to be initialized")
	}

	if len(scanner.genericPatterns) == 0 {
		t.Error("expected generic patterns to be initialized")
	}
}

func TestScanMemory_AWSKey(t *testing.T) {
	scanner := NewScanner()

	data := []byte("AKIAIOSFODNN7EXAMPLE is my AWS key")

	secrets, err := scanner.ScanMemory(data)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	found := false
	for _, secret := range secrets {
		if secret.Type == "AWS Access Key" {
			found = true
			if secret.Confidence != 0.95 {
				t.Errorf("expected confidence 0.95, got %.2f", secret.Confidence)
			}
		}
	}

	if !found {
		t.Error("expected to find AWS Access Key secret")
	}
}

func TestScanMemory_JWT(t *testing.T) {
	scanner := NewScanner()

	jwtToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	data := []byte("token=" + jwtToken)

	secrets, err := scanner.ScanMemory(data)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	found := false
	for _, secret := range secrets {
		if secret.Type == "JWT Token" {
			found = true
			if len(secret.Value) < 10 {
				t.Error("expected JWT value to be long enough")
			}
		}
	}

	if !found {
		t.Error("expected to find JWT Token secret")
	}
}

func TestScanMemory_PrivateKey(t *testing.T) {
	scanner := NewScanner()

	data := []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...")

	secrets, err := scanner.ScanMemory(data)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	found := false
	for _, secret := range secrets {
		if secret.Type == "Private Key" {
			found = true
			if secret.Confidence != 1.00 {
				t.Errorf("expected confidence 1.00, got %.2f", secret.Confidence)
			}
		}
	}

	if !found {
		t.Error("expected to find Private Key secret")
	}
}

func TestScanMemory_Password(t *testing.T) {
	scanner := NewScanner()

	data := []byte("password=mysecretpass123")

	secrets, err := scanner.ScanMemory(data)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	found := false
	for _, secret := range secrets {
		if secret.Type == "Password Assignment" {
			found = true
			if secret.Confidence != 0.60 {
				t.Errorf("expected confidence 0.60, got %.2f", secret.Confidence)
			}
		}
	}

	if !found {
		t.Error("expected to find Password Assignment secret")
	}
}

func TestScanMemory_Duplicates(t *testing.T) {
	scanner := NewScanner()

	data := []byte("AKIAIOSFODNN7EXAMPLE and AKIAIOSFODNN7EXAMPLE")

	secrets, err := scanner.ScanMemory(data)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	awsKeys := FilterSecretsByType(secrets, "AWS Access Key")
	if len(awsKeys) != 1 {
		t.Errorf("expected 1 unique AWS key, got %d", len(awsKeys))
	}
}

func TestScanMemory_NoMatch(t *testing.T) {
	scanner := NewScanner()

	data := []byte("no secrets here just normal text")

	secrets, err := scanner.ScanMemory(data)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if len(secrets) != 0 {
		t.Errorf("expected no secrets, got %d", len(secrets))
	}
}

func TestScanForPatterns(t *testing.T) {
	scanner := NewScanner()

	data := []byte("Contact: user@example.com, IP: 192.168.1.1, URL: https://example.com")

	matches := scanner.ScanForPatterns(data)

	if len(matches) == 0 {
		t.Error("expected pattern matches")
	}

	emailFound := false
	urlFound := false
	ipFound := false

	for _, m := range matches {
		switch m.Name {
		case "Email":
			if m.Value == "user@example.com" {
				emailFound = true
			}
		case "URL":
			if m.Value == "https://example.com" {
				urlFound = true
			}
		case "IPv4 Address":
			ipFound = true
		}
	}

	if !emailFound {
		t.Error("expected to find email address")
	}
	if !urlFound {
		t.Error("expected to find URL")
	}
	if !ipFound {
		t.Error("expected to find IP address")
	}
}

func TestExtractStrings(t *testing.T) {
	data := []byte("Hello\x00World\x00Test123\x00ABC")

	strings := ExtractStrings(data, 3)

	if len(strings) != 4 {
		t.Errorf("expected 4 strings, got %d", len(strings))
	}

	expected := []string{"Hello", "World", "Test123", "ABC"}
	for i, s := range strings {
		if s != expected[i] {
			t.Errorf("expected '%s', got '%s'", expected[i], s)
		}
	}
}

func TestExtractStrings_MinLength(t *testing.T) {
	data := []byte("Hi\x00World\x00ABC")

	strings := ExtractStrings(data, 5)

	if len(strings) != 1 {
		t.Errorf("expected 1 string (World), got %d", len(strings))
	}

	if strings[0] != "World" {
		t.Errorf("expected 'World', got '%s'", strings[0])
	}
}

func TestExtractStrings_Empty(t *testing.T) {
	data := []byte("\x00\x00\x00")

	strings := ExtractStrings(data, 4)

	if len(strings) != 0 {
		t.Errorf("expected 0 strings, got %d", len(strings))
	}
}

func TestExtractStrings_Single(t *testing.T) {
	data := []byte("Hello")

	strings := ExtractStrings(data, 4)

	if len(strings) != 1 || strings[0] != "Hello" {
		t.Errorf("expected ['Hello'], got %v", strings)
	}
}

func TestExtractStrings_NoNull(t *testing.T) {
	data := []byte("Helloworld")

	strings := ExtractStrings(data, 4)

	if len(strings) != 1 || strings[0] != "Helloworld" {
		t.Errorf("expected ['Helloworld'], got %v", strings)
	}
}

func TestParseMemoryRegions(t *testing.T) {
	content := "00400000-00454000 r-xp 00000000 08:0a 123456    /bin/cat\n" +
		"00653000-00654000 r--p 00053000 08:0a 123456    /bin/cat\n" +
		"7fff12340000-7fff12361000 rw-p 00000000 00:00 123456    /proc/self/maps"

	regions := ParseMemoryRegions(content)

	if len(regions) != 3 {
		t.Errorf("expected 3 regions, got %d", len(regions))
	}

	if regions[0].Permissions != "r-xp" {
		t.Errorf("expected 'r-xp', got '%s'", regions[0].Permissions)
	}

	if regions[0].Mapping != "/bin/cat" {
		t.Errorf("expected '/bin/cat', got '%s'", regions[0].Mapping)
	}

	if regions[0].Size != 0x54000 {
		t.Errorf("expected size 0x54000, got 0x%x", regions[0].Size)
	}
}

func TestParseMemoryRegions_Empty(t *testing.T) {
	regions := ParseMemoryRegions("")
	if len(regions) != 0 {
		t.Errorf("expected 0 regions for empty input, got %d", len(regions))
	}
}

func TestParseProcessInfo(t *testing.T) {
	content := "1 (init) S 0 1 1 0 -1 4194560 1234 0 0 0 100 50 0 0 0 0 1 0 12345 12345678 1024 18446744073709551615 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0"

	processes := ParseProcessInfo(content)

	if len(processes) != 1 {
		t.Fatalf("expected 1 process, got %d", len(processes))
	}

	p := processes[0]
	if p.Name != "init" {
		t.Errorf("expected name 'init', got '%s'", p.Name)
	}

	if p.PID != 1 {
		t.Errorf("expected PID 1, got %d", p.PID)
	}

	if p.State != "S" {
		t.Errorf("expected state 'S', got '%s'", p.State)
	}
}

func TestParseProcessInfo_Empty(t *testing.T) {
	processes := ParseProcessInfo("")
	if len(processes) != 0 {
		t.Errorf("expected 0 processes for empty input, got %d", len(processes))
	}
}

func TestFilterSecretsByConfidence(t *testing.T) {
	secrets := []Secret{
		{Type: "AWS Access Key", Value: "key1", Confidence: 0.95},
		{Type: "AWS Access Key", Value: "key2", Confidence: 0.90},
		{Type: "JWT Token", Value: "token1", Confidence: 0.85},
		{Type: "Password Assignment", Value: "pass1", Confidence: 0.60},
	}

	filtered := FilterSecretsByConfidence(secrets, 0.90)

	if len(filtered) != 2 {
		t.Errorf("expected 2 secrets with confidence >= 0.90, got %d", len(filtered))
	}

	for _, s := range filtered {
		if s.Confidence < 0.90 {
			t.Errorf("filtered secret has confidence below threshold: %.2f", s.Confidence)
		}
	}
}

func TestFilterSecretsByType(t *testing.T) {
	secrets := []Secret{
		{Type: "AWS Access Key", Value: "key1", Confidence: 0.95},
		{Type: "AWS Access Key", Value: "key2", Confidence: 0.90},
		{Type: "JWT Token", Value: "token1", Confidence: 0.85},
	}

	filtered := FilterSecretsByType(secrets, "AWS Access Key")

	if len(filtered) != 2 {
		t.Errorf("expected 2 AWS keys, got %d", len(filtered))
	}

	filtered = FilterSecretsByType(secrets, "JWT Token")
	if len(filtered) != 1 {
		t.Errorf("expected 1 JWT token, got %d", len(filtered))
	}

	filtered = FilterSecretsByType(secrets, "GitHub Token")
	if len(filtered) != 0 {
		t.Errorf("expected 0 GitHub tokens, got %d", len(filtered))
	}
}

func TestAnalyzeMemory(t *testing.T) {
	data := []byte("AKIAIOSFODNN7EXAMPLE user@example.com https://example.com")

	dump := AnalyzeMemory(data)

	if dump == nil {
		t.Fatal("expected non-nil MemoryDump")
	}

	if dump.DataSize != len(data) {
		t.Errorf("expected data size %d, got %d", len(data), dump.DataSize)
	}

	if dump.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}

	if dump.URLCount < 1 {
		t.Errorf("expected at least 1 URL, got %d", dump.URLCount)
	}

	if dump.EmailCount < 1 {
		t.Errorf("expected at least 1 email, got %d", dump.EmailCount)
	}

	if dump.IPCount < 0 {
		t.Errorf("expected non-negative IP count, got %d", dump.IPCount)
	}
}

func TestAnalyzeMemory_Empty(t *testing.T) {
	dump := AnalyzeMemory([]byte{})

	if dump == nil {
		t.Fatal("expected non-nil MemoryDump for empty data")
	}

	if dump.DataSize != 0 {
		t.Errorf("expected data size 0, got %d", dump.DataSize)
	}
}

func TestExtractContext(t *testing.T) {
	data := []byte("prefix_secret_value_suffix")
	context := extractContext(data, 7, 12)

	if context != "prefix_secret_value_suffix" {
		t.Errorf("expected full string as context, got '%s'", context)
	}
}

func TestExtractContext_NearStart(t *testing.T) {
	data := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	context := extractContext(data, 0, 5)

	if len(context) == 0 {
		t.Error("expected non-empty context near start")
	}
}

func TestExtractContext_NearEnd(t *testing.T) {
	data := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	context := extractContext(data, len(data)-5, len(data))

	if len(context) == 0 {
		t.Error("expected non-empty context near end")
	}
}

func TestParseHex(t *testing.T) {
	val, err := parseHex("ff")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 255 {
		t.Errorf("expected 255, got %d", val)
	}
}

func TestParseHex_Invalid(t *testing.T) {
	_, err := parseHex("zz")
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestParseUint(t *testing.T) {
	val, err := parseUint("42")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 42 {
		t.Errorf("expected 42, got %d", val)
	}
}

func TestParseUint_Invalid(t *testing.T) {
	_, err := parseUint("abc")
	if err == nil {
		t.Error("expected error for invalid integer")
	}
}

func TestByteOffsetToHex(t *testing.T) {
	offset := byteOffsetToHex(0x12345678)
	if offset != "0x12345678" {
		t.Errorf("expected '0x12345678', got '%s'", offset)
	}

	offset = byteOffsetToHex(0)
	if offset != "0x00000000" {
		t.Errorf("expected '0x00000000', got '%s'", offset)
	}
}
