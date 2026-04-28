package alert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// SyslogConfig drives the syslog sink. Network is one of "udp",
// "tcp", "unix", "unixgram", or "tls"; Address is host:port (or a
// filesystem path for the unix variants). Facility names follow the
// classic syslog set; default is "local0".
type SyslogConfig struct {
	Network   string
	Address   string
	Facility  string
	Hostname  string // typically cfg.Hostname; falls back to os.Hostname()
	TLSCAFile string // optional CA cert path for tls; empty = system roots
}

// SyslogSink is an RFC 5424 syslog client. The wire payload is the
// AuditEvent JSON so SIEMs that parse our JSONL file have a single
// schema regardless of transport. Messages bigger than the legacy
// 1024-byte limit are still sent -- modern receivers (rsyslog,
// syslog-ng) accept the full RFC 5424 max of 8192 bytes; if the
// operator's receiver caps shorter, syslog truncation is the
// expected behaviour.
type SyslogSink struct {
	cfg      SyslogConfig
	priority int // pre-computed PRI byte; severity is OR'd in per emit

	mu   sync.Mutex
	conn net.Conn
}

// facilityCodes is the standard syslog facility number set. local0..7
// is the customary range for application-level audit traffic; we
// default to local0 if the operator leaves the field blank.
var facilityCodes = map[string]int{
	"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4,
	"syslog": 5, "lpr": 6, "news": 7, "uucp": 8, "cron": 9,
	"authpriv": 10, "ftp": 11,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19,
	"local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

// NewSyslogSink validates the config, dials the destination, and
// returns a ready-to-emit sink. A dial failure here is fatal --
// callers should treat it as "audit syslog is misconfigured" rather
// than retrying silently. Once dialled, transient write errors
// trigger a single redial on the next Emit.
func NewSyslogSink(cfg SyslogConfig) (*SyslogSink, error) {
	if cfg.Network == "" || cfg.Address == "" {
		return nil, errors.New("syslog sink: network and address required")
	}
	switch cfg.Network {
	case "udp", "tcp", "unix", "unixgram", "tls":
	default:
		return nil, fmt.Errorf("syslog sink: unknown network %q (want udp|tcp|unix|unixgram|tls)", cfg.Network)
	}
	facilityName := strings.ToLower(strings.TrimSpace(cfg.Facility))
	if facilityName == "" {
		facilityName = "local0"
	}
	facility, ok := facilityCodes[facilityName]
	if !ok {
		return nil, fmt.Errorf("syslog sink: unknown facility %q", cfg.Facility)
	}
	if cfg.Hostname == "" {
		if h, err := os.Hostname(); err == nil {
			cfg.Hostname = h
		} else {
			cfg.Hostname = "localhost"
		}
	}

	s := &SyslogSink{cfg: cfg, priority: facility * 8}
	if err := s.dial(); err != nil {
		return nil, err
	}
	return s, nil
}

// Name identifies the sink in error messages.
func (s *SyslogSink) Name() string { return "syslog" }

// Emit formats the event as RFC 5424 and writes it to the
// destination. Mutex-serialised so concurrent calls do not interleave
// bytes on stream-oriented transports (TCP, TLS).
func (s *SyslogSink) Emit(event AuditEvent) error {
	line, err := s.format(event)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		if redialErr := s.dialLocked(); redialErr != nil {
			return redialErr
		}
	}
	if _, err := s.conn.Write(line); err != nil {
		_ = s.conn.Close()
		s.conn = nil
		return fmt.Errorf("syslog sink: write: %w", err)
	}
	return nil
}

// Close releases the connection.
func (s *SyslogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}

func (s *SyslogSink) dial() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dialLocked()
}

// dialLocked establishes the connection. Caller must hold s.mu.
func (s *SyslogSink) dialLocked() error {
	if s.cfg.Network == "tls" {
		tlsCfg, err := s.tlsConfig()
		if err != nil {
			return err
		}
		conn, err := tls.Dial("tcp", s.cfg.Address, tlsCfg)
		if err != nil {
			return fmt.Errorf("syslog sink: tls dial %s: %w", s.cfg.Address, err)
		}
		s.conn = conn
		return nil
	}
	conn, err := net.DialTimeout(s.cfg.Network, s.cfg.Address, 5*time.Second)
	if err != nil {
		return fmt.Errorf("syslog sink: %s dial %s: %w", s.cfg.Network, s.cfg.Address, err)
	}
	s.conn = conn
	return nil
}

func (s *SyslogSink) tlsConfig() (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if s.cfg.TLSCAFile == "" {
		return cfg, nil
	}
	// #nosec G304 -- TLSCAFile is operator-supplied via cfg.Alerts.AuditLog.Syslog.TLSCAFile; the operator owns the daemon config. Not attacker-controlled.
	pem, err := os.ReadFile(s.cfg.TLSCAFile)
	if err != nil {
		return nil, fmt.Errorf("syslog sink: reading TLS CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("syslog sink: TLS CA file %s is not a valid PEM bundle", s.cfg.TLSCAFile)
	}
	cfg.RootCAs = pool
	return cfg, nil
}

// format produces an RFC 5424 line. The MSG body is the JSON-encoded
// event so receivers can parse the structured payload directly.
//
//	<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID - MSG
//
// PRI = facility * 8 + severity-as-syslog-level. STRUCTURED-DATA is
// "-" (we lift everything into the JSON body to avoid duplicate
// representation).
func (s *SyslogSink) format(event AuditEvent) ([]byte, error) {
	body, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("syslog sink: marshal: %w", err)
	}
	pri := s.priority + severityToSyslogLevel(event.Severity)
	ts := event.Timestamp.UTC().Format(time.RFC3339Nano)
	msgID := event.Check
	if msgID == "" {
		msgID = "-"
	}
	procID := os.Getpid()

	line := fmt.Sprintf("<%d>1 %s %s csm %d %s - %s",
		pri, ts, s.cfg.Hostname, procID, msgID, body)

	// RFC 5424 over UDP / unixgram is one datagram per message; over
	// TCP / TLS / unix-stream the receiver expects either octet
	// counting ("nnn ") or LF framing. LF is the common rsyslog
	// default; emit it for stream transports.
	if s.cfg.Network == "tcp" || s.cfg.Network == "tls" || s.cfg.Network == "unix" {
		line += "\n"
	}
	return []byte(line), nil
}

// severityToSyslogLevel maps CSM severity strings onto the standard
// syslog level codes. Critical -> 2 (crit), High -> 3 (err),
// Warning -> 4 (warning), default -> 6 (info).
func severityToSyslogLevel(s string) int {
	switch s {
	case "CRITICAL":
		return 2
	case "HIGH":
		return 3
	case "WARNING":
		return 4
	}
	return 6
}
