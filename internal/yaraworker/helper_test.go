package yaraworker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/workerproc"
	"github.com/pidginhost/csm/internal/yara"
)

// TestMain turns the test binary into a worker when a helper variable is
// set, so tests launch real worker processes without a separate binary.
// CSM_YARA_HELPER serves the workerproc protocol with fakeEngine;
// YARAWORKER_HELPER is the socket worker of the old supervisor's tests.
func TestMain(m *testing.M) {
	if mode := os.Getenv("CSM_YARA_HELPER"); mode != "" {
		os.Exit(runYaraHelper(mode))
	}
	if mode := os.Getenv("YARAWORKER_HELPER"); mode != "" {
		runHelper(mode)
		return
	}
	os.Exit(m.Run())
}

func runYaraHelper(mode string) int {
	conn, err := workerproc.ChildConn()
	if err == nil {
		err = Serve(context.Background(), conn, fakeEngine{})
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "yara helper:", mode, err)
		return 1
	}
	return 0
}

// fakeEngine stands in for YARA-X in builds without it. A source line
// "marker:<word>" becomes a rule named <word> that matches data containing
// <word>; a source containing "syntax error" fails to compile. Compiled rules
// serialize as "FAKE1\n" followed by the words, one per line.
type fakeEngine struct{}

type fakeRules struct{ words []string }

const fakeRulesHeader = "FAKE1\n"

func (fakeEngine) Compile(sources []yara.Source) (Rules, error) {
	var words []string
	for _, src := range sources {
		if bytes.Contains(src.Text, []byte("syntax error")) {
			return nil, fmt.Errorf("compiling %s: syntax error", src.Name)
		}
		for _, line := range strings.Split(string(src.Text), "\n") {
			if w, ok := strings.CutPrefix(strings.TrimSpace(line), "marker:"); ok && w != "" {
				words = append(words, w)
			}
		}
	}
	return &fakeRules{words: words}, nil
}

func (fakeEngine) Load(r io.Reader) (Rules, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	rest, ok := bytes.CutPrefix(data, []byte(fakeRulesHeader))
	if !ok {
		return nil, errors.New("fake engine: not compiled rules")
	}
	var words []string
	for _, w := range strings.Split(string(rest), "\n") {
		if w != "" {
			words = append(words, w)
		}
	}
	return &fakeRules{words: words}, nil
}

func (r *fakeRules) Count() int { return len(r.words) }

func (r *fakeRules) WriteTo(w io.Writer) (int64, error) {
	n, err := io.WriteString(w, fakeRulesHeader+strings.Join(r.words, "\n"))
	return int64(n), err
}

func (r *fakeRules) Scan(data []byte) ([]yara.Match, error) {
	var out []yara.Match
	for _, w := range r.words {
		if bytes.Contains(data, []byte(w)) {
			out = append(out, yara.Match{RuleName: w, Meta: map[string]string{"severity": "critical"}})
		}
	}
	return out, nil
}
