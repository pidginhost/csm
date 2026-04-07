package config

import "time"

// EmailAVConfig holds email antivirus scanning settings.
type EmailAVConfig struct {
	Enabled            bool   `yaml:"enabled"`
	ClamdSocket        string `yaml:"clamd_socket"`
	ScanTimeout        string `yaml:"scan_timeout"`
	MaxAttachmentSize  int64  `yaml:"max_attachment_size"`
	MaxArchiveDepth    int    `yaml:"max_archive_depth"`
	MaxArchiveFiles    int    `yaml:"max_archive_files"`
	MaxExtractionSize  int64  `yaml:"max_extraction_size"`
	QuarantineInfected bool   `yaml:"quarantine_infected"`
	ScanConcurrency    int    `yaml:"scan_concurrency"`
}

// ScanTimeoutDuration parses the ScanTimeout string as a time.Duration.
func (c *EmailAVConfig) ScanTimeoutDuration() time.Duration {
	if c.ScanTimeout == "" {
		return 30 * time.Second
	}
	d, err := time.ParseDuration(c.ScanTimeout)
	if err != nil {
		return 30 * time.Second
	}
	return d
}

// EmailAVDefaults applies default values to an EmailAVConfig.
func EmailAVDefaults(c *EmailAVConfig) {
	if c.ClamdSocket == "" {
		c.ClamdSocket = "/var/run/clamd.scan/clamd.sock"
	}
	if c.ScanTimeout == "" {
		c.ScanTimeout = "30s"
	}
	if c.MaxAttachmentSize == 0 {
		c.MaxAttachmentSize = 25 * 1024 * 1024 // 25 MB
	}
	if c.MaxArchiveDepth == 0 {
		c.MaxArchiveDepth = 1
	}
	if c.MaxArchiveFiles == 0 {
		c.MaxArchiveFiles = 50
	}
	if c.MaxExtractionSize == 0 {
		c.MaxExtractionSize = 100 * 1024 * 1024 // 100 MB
	}
	if c.ScanConcurrency == 0 {
		c.ScanConcurrency = 4
	}
}
