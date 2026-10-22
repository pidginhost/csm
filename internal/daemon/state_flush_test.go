package daemon

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/state"
)

func stateFileHas(t *testing.T, dir, key string) bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatal(err)
	}
	_, ok := entries[key]
	return ok
}

func archiveEntry(t *testing.T, archive, name string) []byte {
	t.Helper()
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	zr, err := zstd.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			t.Fatalf("archive has no %s", name)
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name == name {
			data, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			return data
		}
	}
}

// state.json lags the alert path by up to a minute, so a live export must
// write the pending dedup state before it copies the state directory.
func TestStoreExportFlushesState(t *testing.T) {
	dir := t.TempDir()
	_, restore := openTestBoltStore(t, dir)
	t.Cleanup(restore)
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := &config.Config{StatePath: dir}
	prev := config.Active()
	config.SetActive(cfg)
	t.Cleanup(func() { config.SetActive(prev) })

	first := alert.Finding{Check: "export_probe", Message: "first", Severity: alert.High}
	second := alert.Finding{Check: "export_probe", Message: "second", Severity: alert.High}
	st.Update([]alert.Finding{first})
	st.Update([]alert.Finding{first, second})
	if stateFileHas(t, dir, second.Key()) {
		t.Fatal("precondition: the second update should still be pending")
	}

	dst := filepath.Join(t.TempDir(), "backup.tar.zst")
	args, err := json.Marshal(control.StoreExportArgs{DstPath: dst})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&ControlListener{d: New(cfg, st, nil, "")}).handleStoreExport(args); err != nil {
		t.Fatal(err)
	}

	var exported map[string]json.RawMessage
	if err := json.Unmarshal(archiveEntry(t, dst, "state/state.json"), &exported); err != nil {
		t.Fatal(err)
	}
	if _, ok := exported[second.Key()]; !ok {
		t.Fatal("export copied state.json without the pending dedup change")
	}
}

func TestAlertDispatcherTickFlushesDueState(t *testing.T) {
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	prevInterval := alertBatchInterval
	alertBatchInterval = 20 * time.Millisecond
	t.Cleanup(func() { alertBatchInterval = prevInterval })

	// SetRaw only marks the store dirty; nothing writes it until a save.
	st.SetRaw("_dispatcher_flush_probe", "pending")
	d := New(&config.Config{StatePath: dir}, st, nil, "")
	d.wg.Add(1)
	go d.alertDispatcher()
	t.Cleanup(func() {
		close(d.stopCh)
		d.wg.Wait()
	})

	deadline := time.Now().Add(10 * time.Second)
	for !stateFileHas(t, dir, "_dispatcher_flush_probe") {
		if time.Now().After(deadline) {
			t.Fatal("dispatcher ticks did not write the pending state")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Close runs only after the workers drain, so a stop that overruns the
// systemd timeout would lose the pending window. The dispatcher writes it as
// soon as it stops.
func TestAlertDispatcherStopFlushesPendingState(t *testing.T) {
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	prevInterval := alertBatchInterval
	alertBatchInterval = time.Hour // no tick may write the state
	t.Cleanup(func() { alertBatchInterval = prevInterval })

	st.SetRaw("_dispatcher_stop_probe", "pending")
	d := New(&config.Config{StatePath: dir}, st, nil, "")
	d.wg.Add(1)
	go d.alertDispatcher()
	close(d.stopCh)
	d.wg.Wait()

	if !stateFileHas(t, dir, "_dispatcher_stop_probe") {
		t.Fatal("dispatcher stopped without writing the pending state")
	}
}
