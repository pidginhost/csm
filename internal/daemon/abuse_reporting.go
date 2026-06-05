package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/reporting"
)

const (
	abuseReportSpoolFile    = "abuse_reports.db"
	abuseReportSpoolDefault = 10000
	abuseReportQueueDefault = abuseReportSpoolDefault
	abuseReportDrainEvery   = time.Minute
)

// startAbuseReporting wires the abuse reporter from config: it sets
// alert.ReportHook so confirmed-abuse findings are gated, minimized, and
// queued for spooling, and returns the spool drain loop to run as a supervised
// goroutine.
// It returns nil when reporting is disabled or misconfigured (logged), leaving
// the alert path untouched.
func (d *Daemon) startAbuseReporting() func() {
	alert.SetReportHook(nil)

	rc := d.cfg.Reputation.Report
	if !rc.Enabled {
		return nil
	}
	targets := buildReportTargets(rc.Targets)
	if len(targets) == 0 {
		log.Printf("abuse-reporting: enabled but no usable targets configured; reporting stays off")
		return nil
	}
	enabled := classSet(rc.Classes)
	if len(enabled) == 0 {
		log.Printf("abuse-reporting: enabled but no valid classes configured; reporting stays off")
		return nil
	}

	spoolPath := rc.SpoolPath
	if spoolPath == "" {
		spoolPath = filepath.Join(d.cfg.StatePath, abuseReportSpoolFile)
	}
	max := rc.SpoolMax
	if max <= 0 {
		max = abuseReportSpoolDefault
	}
	spool, err := reporting.NewSpool(spoolPath, "reports", max)
	if err != nil {
		log.Printf("abuse-reporting: cannot open spool %s: %v; reporting stays off", spoolPath, err)
		return nil
	}

	reportQueue := make(chan reporting.Report, abuseReportQueueSize(max))
	spooler := reporting.NewSpooler(spool, reporting.NewSender(nil, nil), targets, abuseReportDrainEvery)
	gate := reporting.Gate{Enabled: enabled}
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	d.abuseReportStop = stopCh
	d.abuseReportDone = doneCh
	var dropped atomic.Uint64
	var loggedDropped uint64
	logDropped := func() {
		n := dropped.Load()
		if n != loggedDropped {
			log.Printf("abuse-reporting: report queue full; dropped %d report(s)", n)
			loggedDropped = n
		}
	}
	alert.SetReportHook(func(f alert.Finding) {
		if r, ok := gate.Consider(f); ok {
			select {
			case reportQueue <- r:
			default:
				dropped.Add(1)
			}
		}
	})
	log.Printf("abuse-reporting: enabled for %d target(s), %d class(es)", len(targets), len(enabled))

	return func() {
		defer close(doneCh)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			<-stopCh
			cancel()
		}()

		ticker := time.NewTicker(abuseReportDrainEvery)
		defer ticker.Stop()
		defer func() {
			alert.SetReportHook(nil)
			_ = spool.Close()
		}()

		for {
			select {
			case r := <-reportQueue:
				spooler.Enqueue(r)
			case <-ticker.C:
				logDropped()
				spooler.DrainOnce(ctx)
			case <-stopCh:
				alert.SetReportHook(nil)
				logDropped()
				drainReportQueue(spooler, reportQueue)
				return
			}
		}
	}
}

func (d *Daemon) stopAbuseReporting() {
	if d.abuseReportStop == nil {
		return
	}
	close(d.abuseReportStop)
	<-d.abuseReportDone
	d.abuseReportStop = nil
	d.abuseReportDone = nil
}

func abuseReportQueueSize(spoolMax int) int {
	if spoolMax > 0 && spoolMax < abuseReportQueueDefault {
		return spoolMax
	}
	return abuseReportQueueDefault
}

func drainReportQueue(spooler *reporting.Spooler, reportQueue <-chan reporting.Report) {
	for {
		select {
		case r := <-reportQueue:
			spooler.Enqueue(r)
		default:
			return
		}
	}
}

// classSet parses configured class names into the set the gate accepts,
// skipping unknown values with a log line.
func classSet(names []string) map[reporting.Class]bool {
	known := map[reporting.Class]bool{
		reporting.ClassBruteforce:         true,
		reporting.ClassPHPRelay:           true,
		reporting.ClassCredentialStuffing: true,
		reporting.ClassBadASNEgress:       true,
	}
	out := make(map[reporting.Class]bool)
	for _, n := range names {
		c := reporting.Class(n)
		if known[c] {
			out[c] = true
		} else {
			log.Printf("abuse-reporting: ignoring unknown report class %q", n)
		}
	}
	return out
}

// reportTargetConfig mirrors the per-target config shape; declared so the
// builder takes a concrete slice type from the anonymous struct in config.
type reportTargetConfig = struct {
	Name      string `yaml:"name"`
	URL       string `yaml:"url"`
	Transport string `yaml:"transport"`
	NodeID    string `yaml:"node_id"`
	KeyID     string `yaml:"key_id"`
	KeyEnv    string `yaml:"key_env"`
	TokenEnv  string `yaml:"token_env"`
}

// buildReportTargets resolves configured targets into sender targets, reading
// key material from the environment. Invalid targets are skipped with a log
// line rather than failing startup.
func buildReportTargets(cfgTargets []reportTargetConfig) []reporting.Target {
	var targets []reporting.Target
	for _, ct := range cfgTargets {
		if ct.Name == "" || ct.URL == "" || ct.NodeID == "" || ct.KeyID == "" {
			log.Printf("abuse-reporting: skipping target with missing name/url/node_id/key_id")
			continue
		}
		if err := reporting.ValidateTargetURL(ct.URL); err != nil {
			log.Printf("abuse-reporting: target %q: URL must be HTTPS or loopback HTTP; skipping", ct.Name)
			continue
		}
		t := reporting.Target{
			Name:   ct.Name,
			URL:    ct.URL,
			NodeID: ct.NodeID,
			KeyID:  ct.KeyID,
		}
		secret := os.Getenv(ct.KeyEnv)
		switch reporting.Transport(ct.Transport) {
		case reporting.TransportEd25519:
			raw, err := hex.DecodeString(secret)
			if err != nil || len(raw) != ed25519.PrivateKeySize {
				log.Printf("abuse-reporting: target %q: configured key_env must hold a 64-byte hex Ed25519 key; skipping", ct.Name)
				continue
			}
			t.Transport = reporting.TransportEd25519
			t.Ed25519Key = ed25519.PrivateKey(raw)
		case reporting.TransportHMAC:
			if secret == "" {
				log.Printf("abuse-reporting: target %q: configured key_env is empty; skipping", ct.Name)
				continue
			}
			t.Transport = reporting.TransportHMAC
			t.HMACSecret = []byte(secret)
			if ct.TokenEnv != "" {
				t.BearerToken = os.Getenv(ct.TokenEnv)
			}
		default:
			log.Printf("abuse-reporting: target %q: unknown transport %q; skipping", ct.Name, ct.Transport)
			continue
		}
		targets = append(targets, t)
	}
	return targets
}
