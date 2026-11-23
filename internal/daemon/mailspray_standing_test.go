package daemon

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// Losing names at the cap cannot move the start of known failures forward
// and let standing earned during an attack excuse it.
func TestSprayStandingOverflowKeepsEarlierEpisode(t *testing.T) {
	clock := &staticClock{t: standingBase}
	spray := standingSpray(clock)
	cfg := spray.cfg
	cfg.EpisodeWindow = 6 * time.Hour
	spray.SetConfig(cfg)
	spray.Failure(standingIP, standingBox, mailboxExists)
	for range 8 {
		clock.advance(3 * time.Hour)
		spray.Failure(standingIP, standingBox, mailboxExists)
	}
	for i := range maxSprayNamesPerIP {
		spray.Failure(standingIP, fmt.Sprintf("other%d@example.com", i), mailboxExists)
	}
	failed, since := spray.FailedOn(standingIP, standingBox, 6*time.Hour)
	if !failed || !since.Equal(standingBase) {
		t.Fatalf("FailedOn = %v, %v; want true, %v", failed, since, standingBase)
	}
}

func TestSprayStandingUsesEarliestActiveMailboxEpisode(t *testing.T) {
	clock := &staticClock{t: standingBase}
	spray := standingSpray(clock)
	spray.Failure(standingIP, otherBox, mailboxExists)
	clock.advance(time.Minute)
	spray.Failure(standingIP, standingBox, mailboxExists)
	failed, since := spray.FailedOn(standingIP, standingBox, 6*time.Hour)
	if !failed || !since.Equal(standingBase) {
		t.Fatalf("a later mailbox moved the episode start: %v, %v", failed, since)
	}
}

// One protocol can keep an episode active through other mailboxes while
// the other protocol's last failure on this mailbox leaves the window.
func TestSprayStandingMergesOverlappingEpisodes(t *testing.T) {
	for _, mode := range []string{"live", "load", "reverse load"} {
		t.Run(mode, func(t *testing.T) {
			clock := &staticClock{t: standingBase.Add(6 * time.Hour)}
			spray := standingSpray(clock)
			cfg := spray.cfg
			cfg.EpisodeWindow = 6 * time.Hour
			spray.SetConfig(cfg)
			spray.failureInEpisode(standingIP, standingBox, mailboxExists, standingBase, cfg.EpisodeWindow)
			first := spray.Export()
			clock.advance(9 * time.Hour)
			if mode == "live" {
				spray.failureInEpisode(standingIP, standingBox, mailboxExists, standingBase.Add(3*time.Hour), cfg.EpisodeWindow)
			} else {
				later := newMailSpray(cfg, clock.Now)
				later.failureInEpisode(standingIP, standingBox, mailboxExists, standingBase.Add(3*time.Hour), cfg.EpisodeWindow)
				second := later.Export()
				if mode == "reverse load" {
					first, second = second, first
				}
				if err := spray.Load(func(consume func(store.MailSprayState)) error { consume(first); consume(second); return nil }); err != nil {
					t.Fatal(err)
				}
			}
			failed, since := spray.FailedOn(standingIP, standingBox, cfg.EpisodeWindow)
			if !failed || !since.Equal(standingBase) {
				t.Fatalf("overlapping episodes lost their earliest start: %v, %v", failed, since)
			}
		})
	}
}

// A shorter spray-retention setting must not erase failures while the
// trackers still consider them part of the current episode.
func TestSprayStandingRetainsLongerTrackerWindow(t *testing.T) {
	for _, reload := range []bool{false, true} {
		t.Run(fmt.Sprintf("reload=%v", reload), func(t *testing.T) {
			clock := &staticClock{t: standingBase}
			spray := standingSpray(clock)
			cfg := spray.cfg
			cfg.Window, cfg.EpisodeWindow = time.Hour, 6*time.Hour
			spray.SetConfig(cfg)
			spray.Failure(standingIP, standingBox, mailboxExists)
			clock.advance(2 * time.Hour)
			if reload {
				saved := spray.Export()
				if err := spray.Load(func(consume func(store.MailSprayState)) error { consume(saved); return nil }); err != nil {
					t.Fatal(err)
				}
			} else {
				spray.Purge()
			}
			failed, since := spray.FailedOn(standingIP, standingBox, cfg.EpisodeWindow)
			if !failed || !since.Equal(standingBase) {
				t.Fatalf("active tracker failure was lost: %v, %v", failed, since)
			}
		})
	}
}
