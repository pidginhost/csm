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
//	auto    - try file (must exist); fall back to journal if file missing
//	          but units are configured.
//	file    - error if the file doesn't exist.
//	journal - error if the journal reader is unavailable (default builds).
func New(cfg config.MailLogsConfig, platformDefaultFile string) (Reader, error) {
	path := cfg.File
	if path == "" {
		path = platformDefaultFile
	}

	switch cfg.Source {
	case "file":
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("mail_logs.source=file but %s: %w", path, err)
		}
		return NewFileReader(path), nil
	case "journal":
		if len(cfg.Units) == 0 {
			return nil, fmt.Errorf("mail_logs.source=journal requires units")
		}
		return NewJournalReader(cfg.Units), nil
	case "auto":
		if path != "" {
			if _, err := os.Stat(path); err == nil {
				return NewFileReader(path), nil
			}
		}
		if len(cfg.Units) == 0 {
			return nil, errors.New("mail_logs.source=auto: log file not found and no units configured for journal fallback")
		}
		return NewJournalReader(cfg.Units), nil
	default:
		return nil, fmt.Errorf("mail_logs.source=%q: unknown", cfg.Source)
	}
}
