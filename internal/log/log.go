// Package log provides a structured-logging wrapper around log/slog.
//
// Rationale: CSM's daemon currently emits timestamped log lines via direct
// fmt.Fprintf(os.Stderr, ...) calls. That works for journalctl but loses
// structure when operators ship logs to Loki, ELK, or Datadog. This
// package provides a drop-in replacement that:
//
//   - Emits the same human-readable format by default (text handler)
//   - Switches to JSON on CSM_LOG_FORMAT=json for log-shipping pipelines
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
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
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
		return slog.NewTextHandler(os.Stderr, opts)
	}
}
