# memforens - Memory Forensics Toolkit

[![Go](https://img.shields.io/badge/Go-1.21-blue)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A Go library and CLI tool for memory forensics. Detect secrets, credentials, and security artifacts in binary data and memory dumps.

## Features

- Secret detection (AWS keys, GitHub tokens, JWTs, private keys, passwords)
- Pattern matching for URLs, email addresses, and IP addresses
- Printable string extraction from binary data
- Memory region parsing (/proc/self/maps format)
- Process info parsing (/proc/pid/stat format)
- Confidence scoring for each detection

## Installation

### Build from source

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

## Usage

### Scan for secrets

```bash
memforens scan memory.dump
```

### Full analysis

```bash
memforens analyze memory.dump
```

### Programmatic usage

```go
package main

import (
    "fmt"
    "os"

    "github.com/hallucinaut/memforens/pkg/forensics"
)

func main() {
    data, err := os.ReadFile("memory.dump")
    if err != nil {
        panic(err)
    }

    scanner := forensics.NewScanner()

    secrets, err := scanner.ScanMemory(data)
    if err != nil {
        panic(err)
    }

    highConfidence := forensics.FilterSecretsByConfidence(secrets, 0.90)

    fmt.Printf("Found %d high-confidence secrets\n", len(highConfidence))
    for _, secret := range highConfidence {
        fmt.Printf("- %s: %s (%.0f%% confidence)\n",
            secret.Type, secret.Value, secret.Confidence*100)
    }
}
```

## Supported Secret Types

| Type | Confidence | Example Pattern |
|------|------------|-----------------|
| AWS Access Key | 95% | `AKIAIOSFODNN7EXAMPLE` |
| AWS Secret Key | 90% | `aws_secret_access_key=...` |
| GitHub Token | 95% | `ghp_xxxxxxxxxxxxxxxxxxxx...` |
| Generic API Key | 70% | `api_key=xxxxxxxx` |
| JWT Token | 85% | `eyJhbGciOiJIUzI1NiJ9...` |
| Private Key | 100% | `-----BEGIN RSA PRIVATE KEY-----` |
| Password Assignment | 60% | `password=secret123` |

## Testing

```bash
go test ./...
go test -cover ./...
go test -v ./pkg/forensics -run TestScanMemory
```

## Example Output

```
Scanning: memory.dump
File size: 1048576 bytes

Found 5 potential secrets:

[1] Type: AWS Access Key
    Value: AKIAIOSFODNN7EXAMPLE
    Confidence: 95%
    Offset: 0x00000abc

[2] Type: GitHub Token
    Value: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    Confidence: 95%
    Offset: 0x00001def

[3] Type: JWT Token
    Value: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
    Confidence: 85%
    Offset: 0x00002ghi

[4] Type: Private Key
    Value: -----BEGIN RSA PRIVATE KEY-----
    Confidence: 100%
    Offset: 0x00003jkl

[5] Type: Password Assignment
    Value: secret123
    Confidence: 60%
    Offset: 0x00004mno
```

## Architecture

```
memforens/
├── cmd/
│   └── memforens/
│       └── main.go          # CLI entry point
├── pkg/
│   └── forensics/
│       ├── memory.go        # Core analysis engine
│       └── memory_test.go   # Unit tests
├── go.mod
├── LICENSE
└── README.md
```

## Use Cases

- Incident response: analyze memory dumps from compromised systems
- Threat hunting: search for indicators of compromise in memory
- Malware analysis: extract secrets and artifacts from samples
- Compliance audits: verify no secrets remain in memory snapshots
- Security research: study memory artifacts for new attack vectors

## Disclaimer

This tool is for legitimate security research and incident response only. Ensure you have proper authorization before analyzing any memory dump or binary file.

## License

MIT License - see [LICENSE](LICENSE) for details.
