package main

import (
	"fmt"
	"os"

	"github.com/hallucinaut/memforens/pkg/forensics"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "scan":
		if len(os.Args) < 3 {
			fmt.Println("Error: file path required")
			printUsage()
			return
		}
		scanFile(os.Args[2])
	case "analyze":
		if len(os.Args) < 3 {
			fmt.Println("Error: file path required")
			printUsage()
			return
		}
		analyzeFile(os.Args[2])
	case "version":
		fmt.Printf("memforens version %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
	}
}

func printUsage() {
	fmt.Printf(`memforens - Memory Forensics Toolkit

Usage:
  memforens <command> [options]

Commands:
  scan <file>     Scan file for secrets and credentials
  analyze <file>  Analyze file for memory artifacts
  version         Show version information
  help            Show this help message

Examples:
  memforens scan memory.dump
  memforens analyze /proc/meminfo
`)
}

func scanFile(filepath string) {
	scanner := forensics.NewScanner()
	
	// Read file
	data, err := os.ReadFile(filepath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Scanning: %s\n", filepath)
	fmt.Printf("File size: %d bytes\n\n", len(data))

	// Scan for secrets
	secrets, err := scanner.ScanMemory(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d potential secrets:\n\n", len(secrets))

	for i, secret := range secrets {
		fmt.Printf("[%d] Type: %s\n", i+1, secret.Type)
		fmt.Printf("    Value: %s\n", secret.Value)
		fmt.Printf("    Confidence: %.0f%%\n\n", secret.Confidence*100)
	}
}

func analyzeFile(filepath string) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Analyzing: %s\n", filepath)
	fmt.Printf("File size: %d bytes\n\n", len(data))

	dump := forensics.AnalyzeMemory(data)

	fmt.Printf("Architecture: %s\n", dump.Architecture)
	fmt.Printf("OS: %s\n", dump.OS)
	fmt.Printf("Analysis Time: %s\n\n", dump.AnalysisTime)

	fmt.Printf("Secrets Found: %d\n", len(dump.Secrets))
	if len(dump.Secrets) > 0 {
		for _, secret := range dump.Secrets {
			fmt.Printf("  - %s (confidence: %.0f%%)\n", secret.Type, secret.Confidence*100)
		}
	}

	strings := forensics.ExtractStrings(data, 8)
	fmt.Printf("Extracted Strings: %d\n", len(strings))
}