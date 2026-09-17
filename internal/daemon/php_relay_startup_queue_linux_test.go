//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/store"
)

func phpRelayStartupQueueFixture(t *testing.T) (*Daemon, phpRelayPaths, func()) {
	t.Helper()
	root := t.TempDir()
	paths := phpRelayPaths{
		cpanelConfig: filepath.Join(root, "cpanel.config"),
		spool:        filepath.Join(root, "spool"),
		historyLog:   filepath.Join(root, "exim_mainlog"),
		auditLog:     filepath.Join(root, "audit.jsonl"),
	}
	if err := os.WriteFile(paths.cpanelConfig, []byte("maxemailsperhour=100\n"), 0600); err != nil {
		t.Fatal(err)
	}
	oldDB, oldEvaluator := store.Global(), PHPRelayEvaluator()
	db := openTestDB(t)
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(oldDB)
		SetPHPRelayEvaluator(oldEvaluator)
	})
	cfg := &config.Config{StatePath: root}
	cfg.EmailProtection.PHPRelay.PoliciesDir = root
	d := &Daemon{
		cfg:             cfg,
		alertCh:         make(chan alert.Finding, 16),
		stopCh:          make(chan struct{}),
		controlListener: &ControlListener{},
	}
	stop := sync.OnceFunc(func() {
		close(d.stopCh)
		done := make(chan struct{})
		go func() {
			d.wg.Wait()
			for i := len(d.phpRelayShutdown) - 1; i >= 0; i-- {
				d.phpRelayShutdown[i]()
			}
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("PHP relay startup workers did not stop")
		}
	})
	t.Cleanup(stop)
	return d, paths, stop
}

func TestPHPRelayStartupPublishesQueueOwners(t *testing.T) {
	d, paths, stop := phpRelayStartupQueueFixture(t)
	if err := os.Mkdir(paths.spool, 0700); err != nil {
		t.Fatal(err)
	}
	startPHPRelayLinuxAt(d, paths)
	deadline := time.Now().Add(5 * time.Second)
	var rows map[string]queuehealth.Status
	for {
		rows = d.QueueStatuses()
		_, index := rows["phprelay.index.persistence"]
		_, kernel := rows["phprelay.kernel"]
		_, reader := rows["phprelay.reader"]
		if index && kernel && reader && d.WatcherStatuses()["phprelay"] {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("actual startup did not publish its queues: index=%v kernel=%v reader=%v", index, kernel, reader)
		}
		time.Sleep(time.Millisecond)
	}
	index, kernel, reader := rows["phprelay.index.persistence"], rows["phprelay.kernel"], rows["phprelay.reader"]
	if index.Capacity != 4096 || index.Depth != 0 || index.InFlight != 0 || index.DroppedTotal != 0 || index.Status != "ok" || kernel.DepthUnit != "bytes" || !kernel.CapacityUnavailable || kernel.DepthUnavailable || kernel.Depth != 0 || kernel.DroppedTotal != 0 || reader.Depth != 0 || reader.InFlight != 0 || reader.DroppedTotal != 0 {
		t.Fatalf("unexpected startup measurements: index=%+v kernel=%+v reader=%+v", index, kernel, reader)
	}
	controller := d.controlListener.phprelay
	if controller == nil || controller.msgIndex == nil || controller.msgIndex.persister == nil {
		t.Fatal("startup did not wire the controller to the actual persister")
	}
	entry := indexEntry{ScriptKey: "alice:mailer.php", CPUser: "alice", At: time.Now()}
	controller.msgIndex.Put("startup-message", entry)
	controller.msgIndex.persister.Flush()
	if got, exists, err := controller.msgIndex.persister.Lookup("startup-message"); err != nil || !exists || got.ScriptKey != entry.ScriptKey || got.CPUser != entry.CPUser || !got.At.Equal(entry.At) {
		t.Fatalf("actual startup persister did not save its work: got=%+v exists=%v err=%v", got, exists, err)
	}
	stop()
	controller.msgIndex.Put("late-message", entry)
	rows = d.QueueStatuses()
	index, indexExists := rows["phprelay.index.persistence"]
	kernel, kernelExists := rows["phprelay.kernel"]
	reader, readerExists := rows["phprelay.reader"]
	if !indexExists || !kernelExists || !readerExists || index.Capacity != 4096 || index.Depth != 0 || index.InFlight != 0 || index.DroppedTotal != 1 || reader.Depth != 0 || reader.InFlight != 0 || reader.DroppedTotal != 0 || kernel.Depth != 0 || kernel.DepthUnavailable || kernel.DroppedTotal != 0 || !kernel.CapacityUnavailable || !kernel.DroppedLowerBound {
		t.Fatalf("shutdown lost the actual owners' final evidence: index=%+v kernel=%+v reader=%+v", index, kernel, reader)
	}
	if _, exists, err := controller.msgIndex.persister.Lookup("late-message"); err != nil || exists {
		t.Fatalf("stopped startup persister saved refused work: exists=%v err=%v", exists, err)
	}
}

func TestPHPRelayStartupFailureKeepsPersistenceHealth(t *testing.T) {
	d, paths, stop := phpRelayStartupQueueFixture(t)
	startPHPRelayLinuxAt(d, paths)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case f := <-d.alertCh:
			if f.Check != "email_php_relay_watcher_failed" {
				continue
			}
			if f.Severity != alert.Critical {
				t.Fatalf("watcher attachment failure changed severity: %+v", f)
			}
		case <-deadline:
			t.Fatal("missing spool did not fail actual watcher attachment")
		}
		break
	}
	stop()
	rows := d.QueueStatuses()
	index, exists := rows["phprelay.index.persistence"]
	if !exists || index.Capacity != 4096 || index.Depth != 0 || index.InFlight != 0 || index.DroppedTotal != 0 || index.Status != "ok" {
		t.Fatalf("watcher refusal hid the independent persistence owner: exists=%v status=%+v", exists, index)
	}
	for _, name := range []string{"phprelay.kernel", "phprelay.reader"} {
		if _, exists := rows[name]; exists {
			t.Fatalf("failed watcher attachment invented an active queue: %s", name)
		}
	}
	if active, exists := d.WatcherStatuses()["phprelay"]; !exists || active {
		t.Fatalf("failed watcher startup was not recorded: active=%v exists=%v", active, exists)
	}
}
