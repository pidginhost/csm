// fixturecheck rejects non-documentation IPv4 literals in repository fixtures
// and, given a terms file, private names anywhere in the repository.
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

func matchesTerm(line []byte, terms []*regexp.Regexp) bool {
	for _, term := range terms {
		if term.Match(line) {
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

// loadTerms reads one case-insensitive regular expression per line. Blank
// lines and lines starting with # are ignored. The file lives outside the
// repository: CI passes it as a file variable, so the names never enter git.
func loadTerms(path string) ([]*regexp.Regexp, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied terms file.
	if err != nil {
		return nil, fmt.Errorf("read terms: %w", err)
	}
	var terms []*regexp.Regexp
	for n, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		term, err := regexp.Compile("(?i)" + line)
		if err != nil {
			// Report the line number only: the pattern itself is private.
			return nil, fmt.Errorf("terms line %d: invalid pattern", n+1)
		}
		terms = append(terms, term)
	}
	if len(terms) == 0 {
		return nil, errors.New("terms file holds no patterns")
	}
	return terms, nil
}

// termsSource loads the terms file when one is named. With required set, a
// missing file is an error so CI cannot silently skip the private-term scan.
func termsSource(path string, required bool) ([]*regexp.Regexp, error) {
	if path == "" {
		if required {
			return nil, errors.New("no terms file: pass -terms or set CSM_PRIVATE_TERMS")
		}
		return nil, nil
	}
	return loadTerms(path)
}

// scanFile reports the violating lines of one file: non-documentation IPv4
// literals in fixtures, private terms everywhere. Fixtures must be regular
// files; elsewhere a symlink is skipped because its target is scanned under
// its own path.
func scanFile(root *os.Root, name string, fixture bool, terms []*regexp.Regexp, output io.Writer) (violations int, scanned bool, err error) {
	info, err := root.Lstat(name)
	if err != nil {
		return 0, false, err
	}
	if !info.Mode().IsRegular() {
		if fixture {
			return 0, false, fmt.Errorf("%s: fixture must be a regular file", name)
		}
		return 0, false, nil
	}
	file, err := root.Open(name)
	if err != nil {
		return 0, false, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	line := 0
	for scanner.Scan() {
		line++
		// Report locations only, never the text, so private data stays out
		// of CI logs.
		if fixture && disallowedIPv4(scanner.Bytes()) {
			if _, err := fmt.Fprintf(output, "%s:%d: non-documentation IPv4 literal\n", name, line); err != nil {
				return 0, false, err
			}
			violations++
		}
		if matchesTerm(scanner.Bytes(), terms) {
			if _, err := fmt.Fprintf(output, "%s:%d: private term\n", name, line); err != nil {
				return 0, false, err
			}
			violations++
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, false, fmt.Errorf("%s: scan: %w", name, err)
	}
	return violations, true, nil
}

func check(directory string, terms []*regexp.Regexp, output io.Writer) error {
	cmd := exec.Command("git", "-C", directory, "ls-files", "--cached", "--others", "--exclude-standard", "-z") // #nosec G204 -- Git options are fixed; the selected directory is one -C argument, never shell code.
	paths, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("list repository files: %w", err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	seen := make(map[string]bool)
	fixtures, scanned, violations := 0, 0, 0
	for _, entry := range bytes.Split(paths, []byte{0}) {
		name := string(entry)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		// A private filename is itself a violation and cannot safely be
		// printed, including through an os.PathError from opening the file.
		if matchesTerm(entry, terms) {
			if _, err = fmt.Fprintln(output, "[redacted path]: private term in filename"); err != nil {
				return err
			}
			violations++
			continue
		}
		fixture := isFixture(name)
		if !fixture && len(terms) == 0 {
			continue
		}
		count, ok, scanErr := scanFile(root, name, fixture, terms, output)
		if scanErr != nil {
			return scanErr
		}
		violations += count
		if !ok {
			continue
		}
		if fixture {
			fixtures++
		}
		scanned++
	}
	if violations > 0 {
		return fmt.Errorf("%d line(s) require sanitisation", violations)
	}
	if fixtures == 0 {
		return errors.New("no repository fixture files found")
	}
	if _, err = fmt.Fprintf(output, "%d fixture file(s) checked; no disallowed IPv4 literals.\n", fixtures); err != nil {
		return err
	}
	if len(terms) == 0 {
		_, err = fmt.Fprintln(output, "private-term scan skipped: no terms file (pass -terms or set CSM_PRIVATE_TERMS).")
		return err
	}
	_, err = fmt.Fprintf(output, "%d file(s) scanned for private terms; none found.\n", scanned)
	return err
}

func main() {
	root := flag.String("root", ".", "repository to check")
	termsPath := flag.String("terms", os.Getenv("CSM_PRIVATE_TERMS"), "file of case-insensitive regular expressions, one per line, that must not appear in any repository file (default: $CSM_PRIVATE_TERMS)")
	requireTerms := flag.Bool("require-terms", false, "fail when no terms file is available")
	flag.Parse()
	terms, err := termsSource(*termsPath, *requireTerms)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := check(*root, terms, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
