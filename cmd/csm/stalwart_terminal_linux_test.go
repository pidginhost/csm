package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type passwordPromptWriter func([]byte) (int, error)

func (w passwordPromptWriter) Write(p []byte) (int, error) { return w(p) }

func TestStalwartTerminalPassword(t *testing.T) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	fd := int(master.Fd())
	if err = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	tty, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer tty.Close()
	attrs := func(t *testing.T) unix.Termios {
		t.Helper()
		state, err := unix.IoctlGetTermios(int(tty.Fd()), getTerminalAttrs)
		if err != nil {
			t.Fatal(err)
		}
		return *state
	}
	before := attrs(t)
	for _, tc := range []struct {
		name, user, input, want string
		wantErr                 error
	}{
		{"enter", "ops", setupTestPassword + "\n", setupTestPassword, nil},
		{"paste both", "", "ops\n" + setupTestPassword + "\n", setupTestPassword, nil},
		{"EOF", "ops", string(before.Cc[unix.VEOF]), "", io.EOF},
		{"interrupt", "ops", "partial", "", context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var prompted bool
			prompt := passwordPromptWriter(func(p []byte) (int, error) {
				switch string(p) {
				case "Stalwart admin password: ", "Stalwart admin user [admin]: ":
					if attrs(t).Lflag&unix.ECHO != 0 {
						t.Fatal("echo enabled at the password prompt")
					}
					if prompted {
						break
					}
					prompted = true
					if _, err := io.WriteString(master, tc.input); err != nil {
						t.Fatal(err)
					}
					if tc.wantErr == context.Canceled {
						cancel()
					}
				case "\n":
				default:
					t.Fatal("unexpected password prompt output")
				}
				return len(p), nil
			})
			deps := stalwartSetupDeps{prompt: prompt, withoutEcho: func(ask func(io.Reader) error) error {
				return withStalwartTerminalInput(ctx, tty, ask)
			}}
			user, got, err := promptStalwartLogin(deps, tc.user, "")
			if !prompted || user != "ops" || got != tc.want || !errors.Is(err, tc.wantErr) {
				t.Fatalf("unexpected password prompt result (err=%v)", err)
			}
			if attrs(t) != before {
				t.Fatal("terminal settings were not restored")
			}
			if _, err := io.WriteString(master, "next\n"); err != nil {
				t.Fatal(err)
			}
			if next, err := readStalwartLine(tty); err != nil || next != "next" {
				t.Fatal("setup left password input for the next terminal reader")
			}
		})
	}
}
