package yaraworker

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
)

// Config is what the `csm yara-worker` subcommand receives from its
// parent process. SocketPath and RulesDir are mandatory; ErrorLog is
// optional.
type Config struct {
	SocketPath string
	RulesDir   string
	ErrorLog   func(error)
}

// Run is the entrypoint the `csm yara-worker` subcommand calls. It
// binds the Unix socket, compiles rules, and serves until ctx is
// cancelled or an unrecoverable accept error occurs.
//
// Rule-compile failures at startup are not fatal: the worker still
// serves and returns zero matches, so the supervisor can observe the
// condition via Ping and the next OpReload can recover. A fatal failure
// here (bad socket path, permission denied on bind, stale socket that
// cannot be removed) is returned so systemd sees a non-zero exit and
// the supervisor escalates through its backoff.
func Run(ctx context.Context, cfg Config) error {
	if cfg.SocketPath == "" {
		return fmt.Errorf("yaraworker: socket path is empty")
	}

	if err := os.MkdirAll(filepath.Dir(cfg.SocketPath), 0o700); err != nil {
		return fmt.Errorf("yaraworker: mkdir socket dir: %w", err)
	}

	// A stale socket file from a previous worker crash blocks bind.
	// The supervisor only starts one worker at a time, so there is no
	// concurrent binder to race with.
	if err := os.Remove(cfg.SocketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("yaraworker: removing stale socket: %w", err)
	}

	ln, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("yaraworker: listen: %w", err)
	}
	if err := os.Chmod(cfg.SocketPath, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("yaraworker: chmod socket: %w", err)
	}

	scanner, compileErr := yara.NewScanner(cfg.RulesDir)
	compileErrStr := ""
	if compileErr != nil {
		compileErrStr = compileErr.Error()
		if cfg.ErrorLog != nil {
			cfg.ErrorLog(fmt.Errorf("yaraworker: scanner init: %w", compileErr))
		}
	}

	// A failed startup compile is not permanent: give the handler a factory so
	// a later OpReload (forge update, SIGHUP) can rebuild from the fixed rules
	// on disk instead of the worker staying silently dead until it crashes.
	rulesDir := cfg.RulesDir
	rebuild := func() (Scanner, error) {
		s, err := yara.NewScanner(rulesDir)
		if err != nil {
			return nil, err
		}
		if s == nil {
			// !yara build: no engine to build.
			return nil, nil
		}
		return s, nil
	}

	h := newRecoverableHandler(asScanner(scanner), rebuild, compileErrStr)
	return yaraipc.Serve(ctx, ln, h, yaraipc.ServeOptions{ErrorLog: cfg.ErrorLog})
}

// asScanner converts a possibly-nil *yara.Scanner into the Scanner interface
// without producing a typed-nil-inside-interface. `*yara.Scanner` is nil in
// two cases: (1) !yara builds always return (nil, nil), and (2) yara-build
// NewScanner returned (nil, err). In both we want an untyped-nil interface so
// the handler's nil fast path fires instead of a method call on a nil pointer.
func asScanner(s *yara.Scanner) Scanner {
	if s == nil {
		return nil
	}
	return s
}
