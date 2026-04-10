package log

import (
	"bytes"
	"context"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"
)

var legacyTSPattern = regexp.MustCompile(`^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] `)

func TestLegacyTextHandler_InfoFormat(t *testing.T) {
	var buf bytes.Buffer
	h := newLegacyTextHandler(&buf, slog.LevelInfo)
	logger := slog.New(h)
	logger.Info("daemon starting")

	out := buf.String()
	if !legacyTSPattern.MatchString(out) {
		t.Errorf("output should start with [YYYY-MM-DD HH:MM:SS], got %q", out)
	}
	if !strings.Contains(out, "daemon starting") {
		t.Errorf("output should contain message, got %q", out)
	}
	// Info records should NOT have a level marker — matches legacy output.
	if strings.Contains(out, "INFO") {
		t.Errorf("info records should not include level marker, got %q", out)
	}
}

func TestLegacyTextHandler_WarnErrorLevelPrefix(t *testing.T) {
	var buf bytes.Buffer
	h := newLegacyTextHandler(&buf, slog.LevelDebug)
	logger := slog.New(h)

	logger.Warn("log not found")
	logger.Error("alert failed")

	out := buf.String()
	if !strings.Contains(out, "WARN: log not found") {
		t.Errorf("warn should have WARN: prefix, got %q", out)
	}
	if !strings.Contains(out, "ERROR: alert failed") {
		t.Errorf("error should have ERROR: prefix, got %q", out)
	}
}

func TestLegacyTextHandler_AttrsAppended(t *testing.T) {
	var buf bytes.Buffer
	h := newLegacyTextHandler(&buf, slog.LevelInfo)
	logger := slog.New(h)
	logger.Info("platform detected", "os", "ubuntu", "panel", "none")

	out := buf.String()
	if !strings.Contains(out, "os=ubuntu") {
		t.Errorf("attrs should appear as key=value, got %q", out)
	}
	if !strings.Contains(out, "panel=none") {
		t.Errorf("multi-attr output missing panel, got %q", out)
	}
}

func TestLegacyTextHandler_QuotesValuesWithSpaces(t *testing.T) {
	var buf bytes.Buffer
	h := newLegacyTextHandler(&buf, slog.LevelInfo)
	logger := slog.New(h)
	logger.Info("scan result", "message", "two words")

	out := buf.String()
	if !strings.Contains(out, `message="two words"`) {
		t.Errorf("values with spaces should be quoted, got %q", out)
	}
}

func TestLegacyTextHandler_DebugSuppressedAboveInfoLevel(t *testing.T) {
	var buf bytes.Buffer
	h := newLegacyTextHandler(&buf, slog.LevelInfo)
	logger := slog.New(h)
	logger.Debug("debug only")

	if buf.Len() != 0 {
		t.Errorf("debug should be suppressed at info level, got %q", buf.String())
	}
}

func TestLegacyTextHandler_WithAttrsInherited(t *testing.T) {
	var buf bytes.Buffer
	h := newLegacyTextHandler(&buf, slog.LevelInfo)
	child := h.WithAttrs([]slog.Attr{slog.String("component", "daemon")})
	rec := slog.NewRecord(time.Now(), slog.LevelInfo, "running", 0)
	if err := child.Handle(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "component=daemon") {
		t.Errorf("WithAttrs should prepend inherited attrs, got %q", out)
	}
}

func TestLegacyTextHandler_EnabledRespectsLevel(t *testing.T) {
	h := newLegacyTextHandler(&bytes.Buffer{}, slog.LevelWarn)
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("info should not be enabled at warn level")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("error should be enabled at warn level")
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		in   string
		want slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"err", slog.LevelError},
		{"gibberish", slog.LevelInfo},
		{"  WARN  ", slog.LevelWarn},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := parseLevel(tt.in); got != tt.want {
				t.Errorf("parseLevel(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestBuildHandler_TextByDefault(t *testing.T) {
	h := buildHandler("", slog.LevelInfo)
	if _, ok := h.(*legacyTextHandler); !ok {
		t.Errorf("default format should yield legacyTextHandler, got %T", h)
	}
}

func TestBuildHandler_JSON(t *testing.T) {
	h := buildHandler("json", slog.LevelInfo)
	if _, ok := h.(*slog.JSONHandler); !ok {
		t.Errorf("json format should yield JSONHandler, got %T", h)
	}
}

func TestBuildHandler_UnknownFormatFallsBackToText(t *testing.T) {
	h := buildHandler("xml", slog.LevelInfo)
	if _, ok := h.(*legacyTextHandler); !ok {
		t.Errorf("unknown format should fall back to legacyTextHandler, got %T", h)
	}
}

func TestL_LazyInit(t *testing.T) {
	// Reset global so we can test the lazy-init branch.
	global.Store(nil)
	logger := L()
	if logger == nil {
		t.Fatal("L() returned nil")
	}
	if L() != logger {
		t.Error("L() should be idempotent after first call")
	}
}

func TestInit_Idempotent(t *testing.T) {
	first := Init()
	second := Init()
	// Both should be valid loggers but not necessarily the same instance
	// (each Init rebuilds the handler).
	if first == nil || second == nil {
		t.Error("Init should return a non-nil logger")
	}
}

func TestHelpers_DoNotPanic(t *testing.T) {
	// Smoke test: make sure the convenience helpers work end-to-end.
	// Output goes to stderr which the test runner captures.
	Debug("debug message", "key", "value")
	Info("info message", "key", "value")
	Warn("warn message", "key", "value")
	Error("error message", "err", "synthetic")
}
