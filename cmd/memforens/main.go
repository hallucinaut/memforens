package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/hallucinaut/memforens/pkg/forensics"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Error: file path required")
			printUsage()
			os.Exit(1)
		}
		runScan(os.Args[2])
	case "analyze":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Error: file path required")
			printUsage()
			os.Exit(1)
		}
		runAnalyze(os.Args[2])
	case "version":
		fmt.Printf("memforens version %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`memforens - Memory Forensics Toolkit

Usage:
  memforens <command> [options]

Commands:
  scan <file>     Scan file for secrets and credentials
  analyze <file>  Analyze file for memory artifacts
  version         Show version information
  help            Show this help message

Examples:
  memforens scan memory.dump
  memforens analyze /proc/meminfo`)
}

func runScan(filepath string) {
	data, err := forensics.ReadMemoryFile(filepath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	scanner := forensics.NewScanner()
	secrets, err := scanner.ScanMemory(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Scanning: %s\n", filepath)
	fmt.Printf("File size: %d bytes\n", len(data))
	fmt.Printf("\nFound %d potential secrets:\n", len(secrets))

	for i, secret := range secrets {
		fmt.Printf("\n[%d] Type: %s\n", i+1, secret.Type)
		fmt.Printf("    Value: %s\n", truncate(secret.Value, 80))
		fmt.Printf("    Confidence: %.0f%%\n", secret.Confidence*100)
		if secret.Location != "" {
			fmt.Printf("    Offset: %s\n", secret.Location)
		}
		if secret.Context != "" {
			fmt.Printf("    Context: %s\n", truncate(secret.Context, 120))
		}
	}

	if len(secrets) == 0 {
		fmt.Println("\nNo secrets detected.")
	}
}

func runAnalyze(filepath string) {
	data, err := forensics.ReadMemoryFile(filepath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	dump := forensics.AnalyzeMemory(data)

	fmt.Printf("Analyzing: %s\n", filepath)
	fmt.Printf("File size: %d bytes\n", dump.DataSize)
	fmt.Printf("Analysis time: %s\n", dump.Timestamp)
	fmt.Println()

	fmt.Printf("Secrets found: %d\n", len(dump.Secrets))
	if len(dump.Secrets) > 0 {
		for _, secret := range dump.Secrets {
			fmt.Printf("  - %s (confidence: %.0f%%)\n", secret.Type, secret.Confidence*100)
		}
	}

	fmt.Println()
	strings := forensics.ExtractStrings(data, 8)
	fmt.Printf("Extracted strings: %d\n", len(strings))
	fmt.Printf("URLs detected: %d\n", dump.URLCount)
	fmt.Printf("Emails detected: %d\n", dump.EmailCount)
	fmt.Printf("IP addresses detected: %d\n", dump.IPCount)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
