//go:build linux

package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/crashsample"
	emime "github.com/pidginhost/csm/internal/mime"
	"github.com/pidginhost/csm/internal/workerproc"
)

// crashSampleRun handles one message whose worker times out, with the
// watcher's crash sample store set to samples, and returns what it answered
// and reported.
func crashSampleRun(t *testing.T, samples *crashsample.Store) ([]recordedResponse, []alert.Finding, string, string) {
	t.Helper()
	timeout := workerFailure(t, workerproc.ReasonTimeout)
	ex := &recordingExtractor{size: 1, extract: func(context.Context, int) (*emime.ExtractionResult, error) { return nil, timeout }}
	sw, ch := strikeWatcher("tempfail", ex)
	sw.setCrashSamples(samples)
	responses := captureResponses(t)
	dir := t.TempDir()
	msgID := "1abcDE-000003-AB"
	buildMinimalEximSpool(t, dir, msgID)
	sw.handleSpoolEvent(bodyEvent(t, dir, msgID))
	return responses(), takeFindings(ch), dir, msgID
}

func TestSpoolCrashSampleSavedWhenEnabled(t *testing.T) {
	store := filepath.Join(t.TempDir(), "parse-crashes")
	_, _, dir, msgID := crashSampleRun(t, crashsample.New(store))
	for _, part := range []struct{ sample, spool string }{{"body", "-D"}, {"header", "-H"}} {
		want, err := os.ReadFile(filepath.Join(dir, msgID+part.spool))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(store, msgID, part.sample))
		if err != nil || string(got) != string(want) {
			t.Fatalf("sample %s = %q, %v; want a copy of %s", part.sample, got, err, part.spool)
		}
	}
}

func TestSpoolCrashSampleNotSavedByDefault(t *testing.T) {
	state := t.TempDir()
	d := &Daemon{cfg: &config.Config{StatePath: state}}
	d.initCrashSamples()
	t.Cleanup(func() { checks.SetCrashSamples(nil) })
	store := filepath.Join(state, "parse-crashes")
	crashSampleRun(t, d.keptCrashSamples())
	if _, err := os.Lstat(store); !os.IsNotExist(err) {
		t.Fatalf("crash samples written with the setting off: %v", err)
	}
}

// A store that cannot be written must not change how the message is handled.
func TestCrashSampleSaveFailureKeepsVerdict(t *testing.T) {
	wantResp, wantFindings, _, _ := crashSampleRun(t, nil)
	root := t.TempDir()
	target := filepath.Join(root, "elsewhere")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(root, "parse-crashes")
	if err := os.Symlink(target, store); err != nil {
		t.Fatal(err)
	}
	gotResp, gotFindings, _, _ := crashSampleRun(t, crashsample.New(store))
	strip := func(rs []recordedResponse) []uint32 {
		var out []uint32
		for _, r := range rs {
			out = append(out, r.response)
		}
		return out
	}
	withoutTimes := func(fs []alert.Finding) []alert.Finding {
		for i := range fs {
			fs[i].Timestamp = time.Time{}
		}
		return fs
	}
	if !reflect.DeepEqual(strip(gotResp), strip(wantResp)) || !reflect.DeepEqual(withoutTimes(gotFindings), withoutTimes(wantFindings)) {
		t.Fatalf("failed save changed the outcome: %v %v, want %v %v", strip(gotResp), gotFindings, strip(wantResp), wantFindings)
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Fatalf("sample written through a link: %v", entries)
	}
}

func TestSpoolNonWorkerFailuresNeverStrikeOrSave(t *testing.T) {
	for _, cause := range []error{workerproc.ErrSpawn, workerproc.ErrBreakerOpen, workerproc.ErrStopped, context.Canceled, context.DeadlineExceeded, syscall.EMFILE, syscall.ENFILE} {
		t.Run(cause.Error(), func(t *testing.T) {
			ex := &recordingExtractor{size: 1, extract: func(context.Context, int) (*emime.ExtractionResult, error) {
				return nil, fmt.Errorf("operation: %w", cause)
			}}
			sw, ch := strikeWatcher("open", ex)
			store := filepath.Join(t.TempDir(), "parse-crashes")
			sw.setCrashSamples(crashsample.New(store))
			captureResponses(t)
			dir := t.TempDir()
			const id = "1abcDE-000005-AB"
			buildMinimalEximSpool(t, dir, id)
			for range sourceKillLimit + 1 {
				evt := bodyEvent(t, dir, id)
				evt.source = "ip:192.0.2.10"
				sw.handleSpoolEvent(evt)
			}
			if sw.mailStrikes.Len() != 0 || sw.sourceKills.Len() != 0 || len(ex.recorded()) != sourceKillLimit+1 {
				t.Fatal("non-worker failure charged to message or source")
			}
			if fs := findingsFor(takeFindings(ch), "email_av_parse_worker_source"); len(fs) != 0 {
				t.Fatalf("non-worker failure raised source findings: %+v", fs)
			}
			if _, err := os.Lstat(store); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("non-worker failure saved a sample: %v", err)
			}
		})
	}
}

// Turning the setting off must not leave customer mail behind.
func TestCrashSamplesSweptWhenDisabled(t *testing.T) {
	state := t.TempDir()
	cfg := &config.Config{StatePath: state}
	d := &Daemon{cfg: cfg}
	d.initCrashSamples()
	t.Cleanup(func() { checks.SetCrashSamples(nil) })
	if d.keptCrashSamples() != nil {
		t.Fatal("crash samples kept with the setting off")
	}
	old := filepath.Join(state, "parse-crashes", "1abcDE-000004-AB")
	if err := os.MkdirAll(old, 0o700); err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(old, at, at); err != nil {
		t.Fatal(err)
	}
	d.sweepCrashSamples()
	if _, err := os.Lstat(old); !os.IsNotExist(err) {
		t.Fatalf("8-day-old sample survived the sweep: %v", err)
	}
}
