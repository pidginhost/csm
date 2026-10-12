package antispam

import (
	"errors"
	"strings"
	"testing"
)

func TestParseEximSize(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
	}{
		{"50M", 50 << 20}, {"50m", 50 << 20}, {"52428800", 52428800},
		{" 100K ", 100 << 10}, {"1G", 1 << 30}, {"0", 0},
	} {
		if got, err := ParseEximSize(tc.in); err != nil || got != tc.want {
			t.Errorf("ParseEximSize(%q) = %d, %v; want %d", tc.in, got, err, tc.want)
		}
	}
	for _, in := range []string{"", "M", "50MB", "1.5M", "-1", "${if def:x{1}{2}}", "50 M", "99999999999999999999", "8589934592G"} {
		if got, err := ParseEximSize(in); err == nil {
			t.Errorf("ParseEximSize(%q) = %d, want an error", in, got)
		}
	}
}

func TestMaxMessage(t *testing.T) {
	for in, want := range map[string]int64{
		`{"task_timeout": 8.0}`:     DefaultMaxMessage,
		`{"max_message": 62914560}`: 62914560,
		`{"max_message": 0}`:        0,
	} {
		if got, err := MaxMessage([]byte(in)); err != nil || got != want {
			t.Errorf("MaxMessage(%s) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "null", "[]", `{"max_message": "60mb"}`, `{"max_message": 6.5e7}`,
		`{"max_message": -1}`, `{"max_message": null}`, `{"max_message": 99999999999999999999}`} {
		if got, err := MaxMessage([]byte(in)); err == nil {
			t.Errorf("MaxMessage(%s) = %d, want an error", in, got)
		}
	}
}

func TestCheckHostMessageSizeProblems(t *testing.T) {
	boom := errors.New("boom")
	withLimit := func(limit string) func(*HostFacts) {
		return func(f *HostFacts) {
			f.EximSettings.Stdout = strings.Replace(eximSettings, "message_size_limit = 50M", limit, 1)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*HostFacts)
		code   string
		sev    Severity
	}{
		{"exim -bP failed", func(f *HostFacts) { f.EximSettings.Err = boom }, CodeEximOptions, Temporary},
		{"limit not reported", withLimit(""), CodeMessageSize, Temporary},
		{"limit is an expansion", withLimit("message_size_limit = ${if def:sender_host_address{50M}{100M}}"), CodeMessageSize, Temporary},
		{"limit unlimited", withLimit("message_size_limit = 0"), CodeMessageSize, Definite},
		{"configdump failed", func(f *HostFacts) { f.RspamdOptions.Err = boom }, CodeMessageSize, Temporary},
		{"max_message unreadable", func(f *HostFacts) { f.RspamdOptions.Stdout = `{"max_message": "60mb"}` }, CodeMessageSize, Temporary},
		// rspamd's default equals cPanel's default Exim limit, with no room
		// for the envelope Exim adds, so a stock host must raise max_message.
		{"rspamd default max_message", func(f *HostFacts) { f.RspamdOptions.Stdout = `{"task_timeout": 8.0}` }, CodeMessageSize, Definite},
		{"max_message one byte short", func(f *HostFacts) {
			f.RspamdOptions.Stdout = `{"max_message": 53477375}`
		}, CodeMessageSize, Definite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := goodFacts()
			tc.mutate(&f)
			got := CheckHost(f)
			if len(got) != 1 {
				t.Fatalf("got %d problems %+v, want exactly one %s", len(got), got, tc.code)
			}
			if got[0].Code != tc.code || got[0].Severity != tc.sev {
				t.Errorf("got %s/%d (%s), want %s/%d", got[0].Code, got[0].Severity, got[0].Detail, tc.code, tc.sev)
			}
		})
	}
}

func TestCheckHostAcceptsCoveringMaxMessage(t *testing.T) {
	for _, options := range []string{`{"max_message": 53477376}`, `{"max_message": 0}`} {
		f := goodFacts()
		f.RspamdOptions.Stdout = options
		if got := CheckHost(f); len(got) != 0 {
			t.Errorf("%s reported %+v", options, got)
		}
	}
}
