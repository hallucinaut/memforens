# memforens - Memory Forensics Toolkit

[![Go](https://img.shields.io/badge/Go-1.21-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**Advanced memory forensics toolkit for security analysis and incident response.**

Extract secrets, analyze memory dumps, and detect security artifacts from memory images for forensic investigations.

## 🚀 Features

- **Secret Detection**: Find AWS keys, API tokens, JWT tokens, private keys, passwords in memory
- **Pattern Analysis**: Detect URLs, emails, IP addresses, and other network artifacts
- **Memory Region Parsing**: Parse /proc/self/maps format for memory mapping analysis
- **Process Analysis**: Extract process information from memory dumps
- **String Extraction**: Extract printable strings from binary memory data
- **Confidence Scoring**: Rate detection confidence for each finding

## 📦 Installation

### Build from Source

```bash
git clone https://github.com/hallucinaut/memforens.git
cd memforens
go build -o memforens ./cmd/memforens
sudo mv memforens /usr/local/bin/
```

### Install via Go

```bash
go install github.com/hallucinaut/memforens/cmd/memforens@latest
```

## 🎯 Usage

### Scan for Secrets

```bash
# Scan a memory dump file
memforens scan memory.dump

# Scan with specific file
memforens scan /path/to/memory_image.raw
```

### Analyze Memory

```bash
# Analyze memory artifacts
memforens analyze memory.dump

# Get full analysis report
memforens analyze /proc/meminfo
```

### Programmatic Usage

```go
package main

import (
    "fmt"
    "os"
    "github.com/hallucinaut/memforens/pkg/forensics"
)

func main() {
    // Read memory dump
    data, err := os.ReadFile("memory.dump")
    if err != nil {
        panic(err)
    }

    // Create scanner
    scanner := forensics.NewScanner()

    // Scan for secrets
    secrets, err := scanner.ScanMemory(data)
    if err != nil {
        panic(err)
    }

    // Filter by confidence
    highConfidence := scanner.GetSecrets(secrets, 0.90)

    fmt.Printf("Found %d high-confidence secrets\n", len(highConfidence))
    for _, secret := range highConfidence {
        fmt.Printf("- %s: %s (%.0f%% confidence)\n", 
            secret.Type, secret.Value, secret.Confidence*100)
    }
}
```

## 🔍 Supported Secret Types

| Type | Confidence | Example Pattern |
|------|------------|-----------------|
| AWS Access Key | 95% | `AKIAIOSFODNN7EXAMPLE` |
| AWS Secret Key | 90% | `aws_secret_access_key=...` |
| GitHub Token | 95% | `ghp_xxxxxxxxxxxxxxxxxxxx...` |
| Generic API Key | 70% | `api_key=xxxxxxxx` |
| JWT Token | 85% | `eyJhbGciOiJIUzI1NiJ9...` |
| Private Key | 100% | `-----BEGIN RSA PRIVATE KEY-----` |
| Password | 60% | `password=secret123` |

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific test
go test -v ./pkg/forensics -run TestScanMemory
```

## 📊 Example Output

```
Scanning: memory.dump
File size: 1048576 bytes

Found 5 potential secrets:

[1] Type: AWS Access Key
    Value: AKIAIOSFODNN7EXAMPLE
    Confidence: 95%

[2] Type: GitHub Token
    Value: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    Confidence: 95%

[3] Type: JWT Token
    Value: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
    Confidence: 85%

[4] Type: Private Key
    Value: -----BEGIN RSA PRIVATE KEY-----
    Confidence: 100%

[5] Type: Password
    Value: secret123
    Confidence: 60%
```

## 🏗️ Architecture

```
memforens/
├── cmd/
│   └── memforens/
│       └── main.go          # CLI entry point
├── pkg/
│   └── forensics/
│       ├── memory.go        # Memory analysis engine
│       └── memory_test.go   # Unit tests
└── README.md
```

## 🔒 Use Cases

- **Incident Response**: Analyze memory dumps from compromised systems
- **Threat Hunting**: Search for indicators of compromise in memory
- **Malware Analysis**: Extract secrets from malware samples
- **Compliance Audits**: Verify no secrets remain in memory dumps
- **Security Research**: Study memory artifacts for new attack vectors

## ⚠️ Disclaimer

This tool is for legitimate security research and incident response only. Always ensure you have proper authorization before analyzing any memory dump.

## 📄 License

MIT License

## 🙏 Acknowledgments

- Memory forensics community
- Go memory analysis libraries
- Security researchers who share detection patterns

---

**Built with GPU by [hallucinaut](https://github.com/hallucinaut)**