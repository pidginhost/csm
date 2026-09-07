//go:build linux

package daemon

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/emailav"
	emime "github.com/pidginhost/csm/internal/mime"
)

// Spool findings reached the alert pipeline with a zero Timestamp, so every
// email AV finding was dated 0001-01-01 in alerts, the web UI and the store.
func TestEmitFindingStampsTimestamp(t *testing.T) {
	ch := make(chan alert.Finding, 1)
	sw := &SpoolWatcher{alertCh: ch}

	before := time.Now()
	sw.emitFinding("email_av_test", alert.Warning, "hello")
	after := time.Now()

	got := <-ch
	if got.Timestamp.IsZero() {
		t.Fatal("Timestamp is zero; the finding would be dated 0001-01-01 everywhere it is shown")
	}
	if got.Timestamp.Before(before) || got.Timestamp.After(after) {
		t.Errorf("Timestamp = %v, want a time within [%v, %v]", got.Timestamp, before, after)
	}
}

// An encrypted archive is not a degraded scanner. It gets its own check so an
// operator can tell "a package arrived that nobody can scan" apart from "our
// scanning is broken", and so the two do not share a rate limiter.
func TestEncryptedArchiveWarningNamesArchiveAndEntry(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	sw := &SpoolWatcher{alertCh: ch}

	sw.emitEncryptedArchiveWarning("1x3U8R-0000000BFoO-1j5I", []emime.EncryptedArchiveEntry{
		{ArchiveName: "documents.zip", Filename: "Report.pdf"},
	}, 0)

	select {
	case got := <-ch:
		if got.Check != "email_av_encrypted_archive" {
			t.Errorf("Check = %q, want email_av_encrypted_archive", got.Check)
		}
		if got.Severity != alert.Warning {
			t.Errorf("Severity = %v, want Warning", got.Severity)
		}
		for _, want := range []string{"1x3U8R-0000000BFoO-1j5I", "documents.zip", "Report.pdf"} {
			if !strings.Contains(got.Message, want) {
				t.Errorf("Message = %q, want it to contain %q", got.Message, want)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("no finding emitted for an encrypted archive")
	}
}

func TestEncryptedArchiveWarningRateLimited(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	sw := &SpoolWatcher{alertCh: ch}
	entries := []emime.EncryptedArchiveEntry{{ArchiveName: "a.zip", Filename: "b.pdf"}}

	sw.emitEncryptedArchiveWarning("msg-1", entries, 0)
	sw.emitEncryptedArchiveWarning("msg-2", entries, 0)

	if len(ch) != 1 {
		t.Fatalf("emitted %d findings for two back-to-back encrypted archives, want 1", len(ch))
	}
}

// The encrypted-archive limiter must not silence a genuinely degraded scanner.
func TestEncryptedArchiveWarningDoesNotSuppressDegraded(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	sw := &SpoolWatcher{alertCh: ch}

	sw.emitEncryptedArchiveWarning("msg-1", []emime.EncryptedArchiveEntry{{ArchiveName: "a.zip", Filename: "b.pdf"}}, 0)
	sw.emitDegradedWarning("all AV engines unavailable")

	if len(ch) != 2 {
		t.Fatalf("emitted %d findings, want 2: the two conditions share no rate limiter", len(ch))
	}
}

func TestEncryptedArchiveWarningSkippedWhenNoEntries(t *testing.T) {
	ch := make(chan alert.Finding, 4)
	sw := &SpoolWatcher{alertCh: ch}

	sw.emitEncryptedArchiveWarning("msg-1", nil, 0)

	if len(ch) != 0 {
		t.Fatalf("emitted %d findings with no encrypted entries, want 0", len(ch))
	}
}

func TestEncryptedArchiveWarningRetriesAfterFullChannel(t *testing.T) {
	ch := make(chan alert.Finding, 1)
	sw := &SpoolWatcher{alertCh: ch}
	ch <- alert.Finding{Check: "already queued"}
	entries := []emime.EncryptedArchiveEntry{{ArchiveName: "a.zip", Filename: "b.pdf"}}
	sw.emitEncryptedArchiveWarning("msg-1", entries, 0)
	<-ch
	sw.emitEncryptedArchiveWarning("msg-2", entries, 0)
	select {
	case got := <-ch:
		if got.Check != "email_av_encrypted_archive" || !strings.Contains(got.Message, "msg-2") {
			t.Fatalf("unexpected warning: %+v", got)
		}
	default:
		t.Fatal("a dropped warning consumed the hourly allowance")
	}
}

func TestEncryptedArchiveWarningConcurrentLimit(t *testing.T) {
	ch := make(chan alert.Finding, 16)
	sw := &SpoolWatcher{alertCh: ch}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			sw.emitEncryptedArchiveWarning("msg", []emime.EncryptedArchiveEntry{{ArchiveName: "a.zip", Filename: "b.pdf"}}, 0)
		})
	}
	wg.Wait()
	if len(ch) != 1 {
		t.Fatalf("got %d warnings, want 1", len(ch))
	}
	sw.lastEncryptedAt = time.Now().Add(-encryptedArchiveAlertInterval - time.Second)
	sw.emitEncryptedArchiveWarning("later", []emime.EncryptedArchiveEntry{{ArchiveName: "a.zip", Filename: "b.pdf"}}, 0)
	if len(ch) != 2 {
		t.Fatalf("got %d warnings after cooldown, want 2", len(ch))
	}
}

// Encrypted members beyond the report limit must not defer delivery, and a
// plain sibling must still reach an AV engine even in tempfail mode.
func TestEncryptedArchiveReportLimitAllowsDeliveryAndScansPlainSibling(t *testing.T) {
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)

	for _, name := range []string{"encrypted.pdf", "second.pdf", "third.pdf"} {
		encrypted, err := zw.CreateRaw(&zip.FileHeader{Name: name, Flags: 1, Method: 99, CompressedSize64: 6, UncompressedSize64: 6})
		if err != nil {
			t.Fatal(err)
		}
		if _, writeErr := encrypted.Write([]byte("opaque")); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	plain, err := zw.Create("plain.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, writeErr := plain.Write([]byte("plain sibling")); writeErr != nil {
		t.Fatal(writeErr)
	}
	if closeErr := zw.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	dir, tempDir := t.TempDir(), t.TempDir()
	const msgID = "1encrypt-000001-AB"
	header := eximPreamble(msgID) + eximHdrLine(' ', "Content-Type: multipart/mixed; boundary=BOUND")
	body := msgID + "-D\n--BOUND\r\nContent-Type: application/zip\r\nContent-Disposition: attachment; filename=documents.zip\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString(archive.Bytes()) + "\r\n--BOUND--\r\n"
	bodyPath := filepath.Join(dir, msgID+"-D")
	for path, contents := range map[string]string{filepath.Join(dir, msgID+"-H"): header, bodyPath: body} {
		if writeErr := os.WriteFile(path, []byte(contents), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	fileFD, err := unix.Open(bodyPath, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	var pipe [2]int
	if pipeErr := unix.Pipe2(pipe[:], unix.O_CLOEXEC|unix.O_NONBLOCK); pipeErr != nil {
		_ = unix.Close(fileFD)
		t.Fatal(pipeErr)
	}
	defer func() { _ = unix.Close(pipe[0]); _ = unix.Close(pipe[1]) }()
	cfg := &config.Config{}
	limits := emime.DefaultLimits()
	cfg.EmailAV.MaxAttachmentSize, cfg.EmailAV.MaxExtractionSize = limits.MaxAttachmentSize, limits.MaxExtractionSize
	cfg.EmailAV.MaxArchiveDepth, cfg.EmailAV.MaxArchiveFiles = limits.MaxArchiveDepth, 2
	cfg.EmailAV.FailMode = "tempfail"
	engine := &recordingEncryptedMailScanner{}
	ch := make(chan alert.Finding, 8)
	sw := &SpoolWatcher{cfg: cfg, alertCh: ch, fd: pipe[1], emailAVTempDir: tempDir,
		orchestrator: emailav.NewOrchestrator([]emailav.Scanner{engine}, time.Second)}
	sw.handleSpoolEvent(spoolEvent{path: bodyPath, fd: fileFD, needResp: true})
	var response [responseSize]byte
	n, err := unix.Read(pipe[0], response[:])
	if err != nil || n != responseSize {
		t.Fatalf("read response: n=%d err=%v", n, err)
	}
	if got := binary.NativeEndian.Uint32(response[4:]); got != FAN_ALLOW {
		t.Fatalf("delivery response = %d, want allow", got)
	}
	if len(engine.bodies) != 2 || string(engine.bodies[1]) != "plain sibling" {
		t.Fatalf("scanned %d parts; plain sibling not scanned", len(engine.bodies))
	}
	if len(ch) != 1 {
		t.Fatalf("got %d findings, want exactly the encrypted warning", len(ch))
	}
	f := <-ch
	if f.Check != "email_av_encrypted_archive" || !strings.Contains(f.Message, "encrypted.pdf in documents.zip") || !strings.Contains(f.Message, "1 additional encrypted member(s)") {
		t.Fatalf("warning = %+v", f)
	}
	staged, err := os.ReadDir(tempDir)
	if err != nil || len(staged) != 0 {
		t.Fatalf("staging files remain: %v, err=%v", staged, err)
	}
}

type recordingEncryptedMailScanner struct{ bodies [][]byte }

func (*recordingEncryptedMailScanner) Name() string    { return "recording" }
func (*recordingEncryptedMailScanner) Available() bool { return true }
func (s *recordingEncryptedMailScanner) Scan(path string) (emailav.Verdict, error) {
	body, err := os.ReadFile(path)
	if err == nil {
		s.bodies = append(s.bodies, body)
	}
	return emailav.Verdict{}, err
}
