package log

import (
	"log/slog"
	"testing"
)

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
	if _, ok := h.(*slog.TextHandler); !ok {
		t.Errorf("default format should yield TextHandler, got %T", h)
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
	if _, ok := h.(*slog.TextHandler); !ok {
		t.Errorf("unknown format should fall back to TextHandler, got %T", h)
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
