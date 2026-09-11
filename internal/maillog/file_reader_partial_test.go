package maillog

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func withPollingMailFile(t *testing.T, test func(*testing.T, string, *os.File, <-chan Line)) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "maillog")
		w, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		out, err := NewFileReader(path, NewQueue()).Run(ctx)
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		test(t, path, w, out)
		cancel()
		synctest.Wait()
		if got, ok := <-out; ok {
			t.Fatalf("unexpected extra line before shutdown: %+v", got)
		}
	})
}

func appendMailAndPoll(t *testing.T, w *os.File, fragment string) {
	t.Helper()
	if _, err := w.WriteString(fragment); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	synctest.Wait()
}

func expectNoMailLine(t *testing.T, out <-chan Line) {
	t.Helper()
	select {
	case line, ok := <-out:
		t.Fatalf("incomplete record emitted or reader stopped: %+v (open=%v)", line, ok)
	default:
	}
}

func TestFileReaderPreservesEverySplit(t *testing.T) {
	for _, line := range []string{
		"Sep  5 host dovecot: imap-login: Disconnected: auth failed, user=<alice@example.test>\n",
		"Sep  5 host postfix/smtpd: warning: SASL LOGIN authentication failed, sasl_username=bob@example.test\n",
	} {
		for split := 1; split < len(line); split++ {
			t.Run(fmt.Sprintf("%d/%d", len(line), split), func(t *testing.T) {
				withPollingMailFile(t, func(t *testing.T, _ string, w *os.File, out <-chan Line) {
					appendMailAndPoll(t, w, line[:split])
					expectNoMailLine(t, out)
					appendMailAndPoll(t, w, "")
					expectNoMailLine(t, out)
					appendMailAndPoll(t, w, line[split:])
					expectMailLine(t, out, line)
				})
			})
		}
	}
}

func TestFileReaderOversizedFragmentsStayDiscarded(t *testing.T) {
	withPollingMailFile(t, func(t *testing.T, _ string, w *os.File, out <-chan Line) {
		for range 3 {
			appendMailAndPoll(t, w, strings.Repeat("A", maxLogLineBytes/2))
			expectNoMailLine(t, out)
		}
		appendMailAndPoll(t, w, "forged suffix\nvalid next line\n")
		expectMailLine(t, out, "valid next line\n")
	})
}

func TestFileReaderPartialStateResetsOnRotation(t *testing.T) {
	for _, truncate := range []bool{false, true} {
		for _, size := range []int{1024, maxLogLineBytes + 10} {
			t.Run(fmt.Sprintf("truncate=%v/size=%d", truncate, size), func(t *testing.T) {
				withPollingMailFile(t, func(t *testing.T, path string, w *os.File, out <-chan Line) {
					appendMailAndPoll(t, w, strings.Repeat("old", size))
					expectNoMailLine(t, out)
					if !truncate {
						if err := os.Rename(path, path+".1"); err != nil {
							t.Fatal(err)
						}
					}
					if err := os.WriteFile(path, []byte("fresh generation\n"), 0600); err != nil {
						t.Fatal(err)
					}
					expectMailLine(t, out, "fresh generation\n")
				})
			})
		}
	}
}

func TestFileReaderCancelsWithPartialLine(t *testing.T) {
	withPollingMailFile(t, func(t *testing.T, _ string, w *os.File, out <-chan Line) {
		appendMailAndPoll(t, w, "unfinished mail record")
		expectNoMailLine(t, out)
	})
}

func TestFileReaderLineLimitIncludesNewline(t *testing.T) {
	for _, extra := range []int{0, 1} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			withPollingMailFile(t, func(t *testing.T, _ string, w *os.File, out <-chan Line) {
				prefix := strings.Repeat("A", maxLogLineBytes-1+extra)
				appendMailAndPoll(t, w, prefix)
				expectNoMailLine(t, out)
				appendMailAndPoll(t, w, "\nnext\n")
				if extra == 0 {
					expectMailLine(t, out, prefix+"\n")
				}
				expectMailLine(t, out, "next\n")
			})
		})
	}
}
