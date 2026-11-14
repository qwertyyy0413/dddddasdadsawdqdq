package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"overbyte-tools/cryptotable"
)

func loadSecrets(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	// allow long lines (domains, tokens)
	const max = 1024 * 1024
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, max)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

func main() {
	secretsPath := flag.String("secrets", "", "path to secrets file (one string per line; lines starting with # are comments)")
	flag.Parse()
	if *secretsPath == "" {
		fmt.Fprintf(os.Stderr, "usage: go run ./enc -secrets <file>\n")
		os.Exit(1)
	}
	secrets, err := loadSecrets(*secretsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enc: %v\n", err)
		os.Exit(1)
	}
	if len(secrets) == 0 {
		fmt.Fprintf(os.Stderr, "enc: no secrets loaded from %s\n", *secretsPath)
		os.Exit(1)
	}
	if err := cryptotable.WriteTableC(os.Stdout, secrets); err != nil {
		fmt.Fprintf(os.Stderr, "enc: write: %v\n", err)
		os.Exit(1)
	}
}
