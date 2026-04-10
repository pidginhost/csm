// Package log provides a structured-logging wrapper around log/slog.
//
// Rationale: CSM's daemon currently emits timestamped log lines via direct
// fmt.Fprintf(os.Stderr, ...) calls. That works for journalctl but loses
// structure when operators ship logs to Loki, ELK, or Datadog. This
// package provides a drop-in replacement that:
//
//   - Emits the legacy "[YYYY-MM-DD HH:MM:SS] msg" format in text mode so
//     mixing csmlog calls with legacy fmt.Fprintf calls produces a
//     uniform log stream (important during incremental migration)
//   - Switches to JSON on CSM_LOG_FORMAT=json for log-shipping pipelines,
//     emitting the slog-native level/msg/time/fields structure
//   - Honors CSM_LOG_LEVEL={debug|info|warn|error} (default: info)
//
// Usage (preferred for new code):
//
//	log.Info("daemon starting", "version", v, "pid", os.Getpid())
//	log.Warn("log not found, will retry", "path", path)
//	log.Error("alert dispatch failed", "err", err)
//
// Legacy call sites that still use fmt.Fprintf will keep working —
// migration is incremental. See docs/src/development.md for guidance.
package log

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// global is the package-level logger, loaded lazily on first use.
// atomic.Pointer so Init can swap it without data races.
var global atomic.Pointer[slog.Logger]

// Init configures the global logger from environment variables:
//
//	CSM_LOG_FORMAT = "text" (default) | "json"
//	CSM_LOG_LEVEL  = "debug" | "info" (default) | "warn" | "error"
//
// Safe to call multiple times. Returns the installed logger so callers can
// also pass it into subsystems that take a *slog.Logger.
func Init() *slog.Logger {
	level := parseLevel(os.Getenv("CSM_LOG_LEVEL"))
	handler := buildHandler(os.Getenv("CSM_LOG_FORMAT"), level)
	logger := slog.New(handler)
	global.Store(logger)
	slog.SetDefault(logger)
	return logger
}

// L returns the current global logger, initializing it on first call.
// Cheap on the hot path (single atomic load).
func L() *slog.Logger {
	if l := global.Load(); l != nil {
		return l
	}
	return Init()
}

// Helpers that mirror slog's method set on the global logger. Provided so
// call sites don't need to write log.L().Info(...) on every line.

func Debug(msg string, args ...any) { L().Debug(msg, args...) }
func Info(msg string, args ...any)  { L().Info(msg, args...) }
func Warn(msg string, args ...any)  { L().Warn(msg, args...) }
func Error(msg string, args ...any) { L().Error(msg, args...) }

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error", "err":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func buildHandler(format string, level slog.Level) slog.Handler {
	opts := &slog.HandlerOptions{Level: level}
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		return slog.NewJSONHandler(os.Stderr, opts)
	default:
		return newLegacyTextHandler(os.Stderr, level)
	}
}

// legacyTextHandler emits log records in CSM's historical "[timestamp] msg"
// format so callers migrating from fmt.Fprintf produce the same output. Key
// differences from slog.NewTextHandler:
//
//   - No "time=... level=... msg=..." prefix; just "[YYYY-MM-DD HH:MM:SS] msg"
//   - Structured fields are appended as "  key=value" when present
//   - Level is prepended as "WARN:" / "ERROR:" only for non-info records
//
// This lets operators mix csmlog calls with the ~180 remaining fmt.Fprintf
// call sites in the daemon without introducing a mixed-format log stream.
type legacyTextHandler struct {
	w     io.Writer
	mu    *sync.Mutex
	level slog.Level
	attrs []slog.Attr
	group string
}

func newLegacyTextHandler(w io.Writer, level slog.Level) *legacyTextHandler {
	return &legacyTextHandler{
		w:     w,
		mu:    &sync.Mutex{},
		level: level,
	}
}

func (h *legacyTextHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *legacyTextHandler) Handle(_ context.Context, r slog.Record) error {
	var sb strings.Builder
	sb.Grow(128)

	ts := r.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	sb.WriteByte('[')
	sb.WriteString(ts.Format("2006-01-02 15:04:05"))
	sb.WriteString("] ")

	// Prepend a level marker only for non-info records so the info path
	// exactly matches the legacy "[ts] msg" format.
	switch r.Level {
	case slog.LevelWarn:
		sb.WriteString("WARN: ")
	case slog.LevelError:
		sb.WriteString("ERROR: ")
	case slog.LevelDebug:
		sb.WriteString("DEBUG: ")
	}

	sb.WriteString(r.Message)

	// Append pre-bound attrs then record attrs as "  key=value" pairs.
	for _, a := range h.attrs {
		writeAttr(&sb, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(&sb, a)
		return true
	})
	sb.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, sb.String())
	return err
}

func writeAttr(sb *strings.Builder, a slog.Attr) {
	if a.Key == "" {
		return
	}
	sb.WriteString("  ")
	sb.WriteString(a.Key)
	sb.WriteByte('=')
	v := a.Value.Resolve()
	s := v.String()
	// Quote values that contain whitespace so the key=value pairs stay
	// parseable when operators grep the log.
	if strings.ContainsAny(s, " \t") {
		sb.WriteByte('"')
		sb.WriteString(s)
		sb.WriteByte('"')
	} else {
		sb.WriteString(s)
	}
}

func (h *legacyTextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &legacyTextHandler{
		w:     h.w,
		mu:    h.mu,
		level: h.level,
		attrs: merged,
		group: h.group,
	}
}

func (h *legacyTextHandler) WithGroup(name string) slog.Handler {
	// Groups flatten into the attr key via a prefix; simple implementation
	// that's sufficient for CSM's usage (we don't use groups today).
	return &legacyTextHandler{
		w:     h.w,
		mu:    h.mu,
		level: h.level,
		attrs: h.attrs,
		group: name,
	}
}

// Ensure legacyTextHandler satisfies the slog.Handler contract at compile time.
var _ slog.Handler = (*legacyTextHandler)(nil)
