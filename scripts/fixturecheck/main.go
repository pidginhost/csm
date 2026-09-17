// fixturecheck rejects non-documentation IPv4 literals in repository fixtures.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var ipv4Literal = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
var documentationRanges = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
}

func disallowedIPv4(line []byte) bool {
	for _, candidate := range ipv4Literal.FindAll(line, -1) {
		ip, err := netip.ParseAddr(string(candidate))
		if err != nil {
			continue
		}
		allowed := false
		for _, prefix := range documentationRanges {
			if prefix.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			return true
		}
	}
	return false
}

func isFixture(path string) bool {
	parts := strings.Split(path, "/")
	for _, part := range parts[:len(parts)-1] {
		if part == "testdata" || part == "fixtures" {
			return true
		}
	}
	return false
}

func scanFixture(root *os.Root, name string, output io.Writer) (int, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("%s: fixture must be a regular file", name)
	}
	file, err := root.Open(name)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	line, violations := 0, 0
	for scanner.Scan() {
		line++
		if disallowedIPv4(scanner.Bytes()) {
			// Report the location without copying potentially private data into CI logs.
			if _, err := fmt.Fprintf(output, "%s:%d: non-documentation IPv4 literal\n", name, line); err != nil {
				return 0, err
			}
			violations++
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("%s: scan: %w", name, err)
	}
	return violations, nil
}

func check(directory string, output io.Writer) error {
	cmd := exec.Command("git", "-C", directory, "ls-files", "--cached", "--others", "--exclude-standard", "-z") // #nosec G204 -- Git options are fixed; the selected directory is one -C argument, never shell code.
	paths, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("list repository fixtures: %w", err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	seen := make(map[string]bool)
	files, violations := 0, 0
	for _, entry := range bytes.Split(paths, []byte{0}) {
		name := string(entry)
		if name == "" || seen[name] || !isFixture(name) {
			continue
		}
		seen[name] = true
		count, scanErr := scanFixture(root, name, output)
		if scanErr != nil {
			return scanErr
		}
		files++
		violations += count
	}
	if files == 0 {
		return errors.New("no repository fixture files found")
	}
	if violations > 0 {
		return fmt.Errorf("%d fixture line(s) require sanitisation", violations)
	}
	_, err = fmt.Fprintf(output, "%d fixture file(s) checked; no disallowed IPv4 literals.\n", files)
	return err
}

func main() {
	root := flag.String("root", ".", "repository to check")
	flag.Parse()
	if err := check(*root, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
