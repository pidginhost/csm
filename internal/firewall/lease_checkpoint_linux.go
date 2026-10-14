//go:build linux

package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/pidginhost/csm/internal/atomicio"
)

// leaseCheckpointFile, beside the state file, keeps the lease clock across
// restarts. Older builds ignore it.
const leaseCheckpointFile = "lease.json"

// leaseCheckpoint is the lease clock as last saved, with the boot it was
// read in and the time since that boot. Within one boot a restart resumes
// at the checkpoint plus the time elapsed since it, whatever the wall clock
// did meanwhile; a new boot proves no downtime and resumes at the
// checkpoint itself (spec 5.4). Clock sampling latency can only shorten
// restoration.
type leaseCheckpoint struct {
	Lease     time.Time     `json:"lease"`
	BootID    string        `json:"boot_id"`
	SinceBoot time.Duration `json:"since_boot"`
}

// SetBootClock gives the engine the boot identity and the time since boot,
// read together. Without it the engine keeps no lease checkpoint.
func (e *Engine) SetBootClock(read func() (bootID string, sinceBoot time.Duration, err error)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.bootClock = read
}

// resumeLeaseLocked moves the lease clock forward to what the saved
// checkpoint proves, once per engine, before its first Apply restores timed
// blocks. A missing checkpoint proves nothing; a damaged one is reported
// and changes nothing.
func (e *Engine) resumeLeaseLocked() error {
	if e.bootClock == nil || e.leaseResumed {
		return nil
	}
	e.leaseResumed = true
	data, err := os.ReadFile(filepath.Join(e.statePath, leaseCheckpointFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var ck leaseCheckpoint
	if err = json.Unmarshal(data, &ck); err != nil || ck.Lease.IsZero() || ck.BootID == "" || ck.SinceBoot < 0 {
		return fmt.Errorf("lease checkpoint is damaged: %w", errors.Join(err, errors.New("invalid checkpoint")))
	}
	// Anchor before the boot read: its latency must not be given back
	// when the resumed floor is later advanced by elapsed time.
	e.leaseNowLocked()
	boot, since, err := e.bootClock()
	if err != nil {
		return err
	}
	floor := ck.Lease
	if boot == ck.BootID && since >= ck.SinceBoot {
		floor = ck.Lease.Add(since - ck.SinceBoot)
	}
	if floor.After(e.lease.now) {
		e.lease.now = floor.Round(0)
	}
	return nil
}

// saveLeaseLocked records the lease clock and the boot reading taken with
// it. Apply saves after installation; timed legacy intents save first so
// their new absolute deadlines cannot outlive the authorized duration.
func (e *Engine) saveLeaseLocked() error {
	if e.bootClock == nil {
		return nil
	}
	// Pair a later lease sample with an earlier boot sample. A slow
	// boot read may shorten restoration, but cannot renew a lease.
	boot, since, err := e.bootClock()
	if err != nil {
		return err
	}
	lease := e.leaseNowLocked()
	return atomicio.AtomicWriteJSON(filepath.Join(e.statePath, leaseCheckpointFile), 0o600, leaseCheckpoint{Lease: lease.UTC(), BootID: boot, SinceBoot: since})
}
