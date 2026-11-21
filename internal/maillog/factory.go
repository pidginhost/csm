package maillog

import (
	"errors"
	"fmt"
	"os"

	"github.com/pidginhost/csm/internal/config"
)

// New returns the mail-log Reader appropriate for cfg.Source. A "platform"
// default file path is supplied by the caller (computed from
// internal/platform.Detect()). Pass an empty string to skip the platform
// default - useful in tests.
//
//	auto    - prefer a usable journal covering the running mail services;
//	          otherwise file, then journal if units are configured.
//	file    - error if the file doesn't exist.
//	journal - select journal; Run errors if journal support is unavailable.
func New(cfg config.MailLogsConfig, platformDefaultFile string, queue *Queue) (Reader, error) {
	journal, err := UsesJournal(cfg, platformDefaultFile)
	if err != nil {
		return nil, err
	}
	if journal {
		return NewJournalReader(cfg.Units, queue), nil
	}
	path := cfg.File
	if path == "" {
		path = platformDefaultFile
	}
	return NewFileReader(path, queue), nil
}

// UsesJournal applies the same source selection as New, including the
// platform file and the missing-file fallback. It reports selection only;
// the reader can still fail when Run opens the selected source.
func UsesJournal(cfg config.MailLogsConfig, platformDefaultFile string) (bool, error) {
	path := cfg.File
	if path == "" {
		path = platformDefaultFile
	}

	switch cfg.Source {
	case "file":
		if _, err := os.Stat(path); err != nil {
			return false, fmt.Errorf("mail_logs.source=file but %s: %w", path, err)
		}
		return false, nil
	case "journal":
		if len(cfg.Units) == 0 {
			return false, fmt.Errorf("mail_logs.source=journal requires units")
		}
		return true, nil
	case "auto":
		// Only journald records who wrote a line; a log file takes any
		// local user's lines under any program name.
		if autoPrefersJournal(cfg) {
			return true, nil
		}
		if path != "" {
			if _, err := os.Stat(path); err == nil {
				return false, nil
			}
		}
		if len(cfg.Units) == 0 {
			return false, errors.New("mail_logs.source=auto: log file not found and no units configured for journal fallback")
		}
		return true, nil
	default:
		return false, fmt.Errorf("mail_logs.source=%q: unknown", cfg.Source)
	}
}

// autoPrefersJournal reports whether source auto reads the journal: it is
// usable, Postfix writes no log file of its own, and the configured units
// cover every running mail master.
func autoPrefersJournal(cfg config.MailLogsConfig) bool {
	return len(cfg.Units) > 0 && JournalUsable() && !postfixLogsToFile() && mailUnitsCovered(cfg.Units)
}
