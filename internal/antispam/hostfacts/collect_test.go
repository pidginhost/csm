package hostfacts

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/platform"
)

type fakeRun struct {
	results map[string]antispam.CommandResult
	calls   []string
}

func (f *fakeRun) run(_ context.Context, name string, args ...string) antispam.CommandResult {
	line := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, line)
	if r, ok := f.results[line]; ok {
		return r
	}
	return antispam.CommandResult{Err: errors.New("command failed")}
}

func lookup(ids map[string]int) func(string) (int, error) {
	return func(name string) (int, error) {
		if id, ok := ids[name]; ok {
			return id, nil
		}
		return -1, fmt.Errorf("unknown %s", name)
	}
}

func testCollector(d string, run *fakeRun) collector {
	return collector{
		layout: Layout{
			GeneratedConf: filepath.Join(d, "exim.conf"),
			LocalConf:     filepath.Join(d, "exim.conf.local"),
			SpamdDisabled: filepath.Join(d, "spamddisable"),
			GlobalEnable:  filepath.Join(d, "global_spamassassin_enable"),
		},
		cpanel:   func() bool { return true },
		eximMTA:  func() bool { return true },
		run:      run.run,
		lookPath: func(string) (string, error) { return "/usr/bin/systemd-run", nil },
		uid:      lookup(map[string]int{"_rspamd": 979, "mailnull": 47}),
		gid:      lookup(map[string]int{"mail": 12}),
	}
}

func TestCollectReadsEveryFact(t *testing.T) {
	d := t.TempDir()
	write(t, filepath.Join(d, "exim.conf"), "generated\n")
	write(t, filepath.Join(d, "exim.conf.local"), "@CONFIG@\n")
	write(t, filepath.Join(d, "spamddisable"), "")
	write(t, filepath.Join(d, "filter"), "if $spam_score_int is above 50 then\n  seen finish\nendif\n")
	mkdir(t, filepath.Join(d, "local.d"))
	write(t, filepath.Join(d, "local.d", "actions.conf"), antispam.ManagedHeader+"\n")
	mkdir(t, filepath.Join(d, "rspamd"))
	sock := serve(t, filepath.Join(d, "rspamd"), pong)

	conf := filepath.Join(d, "exim.conf")
	results := map[string]antispam.CommandResult{
		"exim -bV": {Stdout: "Exim version 4.100.1 #2\n"},
		"exim -bP prdr_enable chunking_advertise_hosts": {Stdout: "no_prdr_enable\n"},
		"exim -bP message_size_limit log_file_path exim_user exim_group system_filter": {
			Stdout: "message_size_limit = 50M\nlog_file_path = /var/log/exim_%slog\nexim_user = mailnull\nexim_group = mail\nsystem_filter = " + filepath.Join(d, "filter") + "\n",
		},
		"rspamd --version":               {Stdout: "Rspamd daemon version 4.2.1\n"},
		"rspamadm --version":             {Stdout: "Rspamadm 4.2.1\n"},
		"rspamadm configdump -j options": {Stdout: `{"max_message": 62914560}`},
		"systemctl show -p LoadState -p User -p CanReload rspamd.service": {Stdout: "User=_rspamd\nLoadState=loaded\nCanReload=yes\n"},
		"systemctl show -p LoadState -p User -p CanReload exim.service":   {Stdout: "User=\nLoadState=loaded\nCanReload=yes\n"},
	}
	for i, probe := range antispam.NamedListProbes() {
		results["exim -C "+conf+" -be "+probe] = antispam.CommandResult{Stdout: fmt.Sprintf("probe %d\n", i)}
	}
	run := &fakeRun{results: results}
	c := testCollector(d, run)
	c.layout.Targets = []antispam.Target{
		{Path: filepath.Join(d, "local.d", "actions.conf"), Kind: antispam.TargetRspamd},
		{Path: filepath.Join(d, "local.d", "rbl.conf"), Kind: antispam.TargetRspamd},
	}

	f := c.collect(context.Background(), sock)

	if !f.CPanel || !f.MTAExim || f.MonitoredLog != platform.EximMainLog {
		t.Errorf("platform facts %t %t %q", f.CPanel, f.MTAExim, f.MonitoredLog)
	}
	if f.EximVersion.Stdout != "Exim version 4.100.1 #2\n" || f.EximOptions.Stdout != "no_prdr_enable\n" ||
		!strings.Contains(f.EximSettings.Stdout, "message_size_limit = 50M") || f.RspamdOptions.Stdout != `{"max_message": 62914560}` ||
		f.RspamdVersion.Stdout == "" || f.RspamadmVersion.Stdout == "" || f.RspamdService.Err != nil || f.EximService.Err != nil {
		t.Errorf("command results %+v", f)
	}
	for i, r := range f.NamedLists {
		if r.Stdout != fmt.Sprintf("probe %d\n", i) {
			t.Errorf("named list %d = %+v; want it run against %s", i, r, conf)
		}
	}
	if len(f.NamedLists) != len(antispam.NamedListProbes()) {
		t.Errorf("%d named-list results", len(f.NamedLists))
	}
	if f.GeneratedConf != "generated\n" || f.GeneratedErr != nil || f.LocalConf != "@CONFIG@\n" || f.LocalErr != nil {
		t.Errorf("config files %q %v %q %v", f.GeneratedConf, f.GeneratedErr, f.LocalConf, f.LocalErr)
	}
	if !f.SpamdDisabled || f.SpamdDisabledErr != nil || f.GlobalEnable {
		t.Errorf("spamd %t %v global %t", f.SpamdDisabled, f.SpamdDisabledErr, f.GlobalEnable)
	}
	if !strings.HasPrefix(f.SystemFilter, "if $spam_score_int") || f.SystemFilterErr != nil || f.SystemdRunErr != nil {
		t.Errorf("filter %q %v systemd-run %v", f.SystemFilter, f.SystemFilterErr, f.SystemdRunErr)
	}
	if len(f.Targets) != 2 || f.Targets[0].Content != antispam.ManagedHeader+"\n" || !f.Targets[1].Missing {
		t.Errorf("targets %+v", f.Targets)
	}
	s := f.Socket
	if s.Err != nil || s.Missing || s.PingErr != nil || s.PeerUID != wantPeer() || s.RspamdUID != 979 || s.EximUID != 47 || s.EximGID != 12 {
		t.Errorf("socket %+v", s)
	}
	want := []string{
		"exim -bV",
		"exim -bP prdr_enable chunking_advertise_hosts",
		"exim -bP message_size_limit log_file_path exim_user exim_group system_filter",
	}
	for _, probe := range antispam.NamedListProbes() {
		want = append(want, "exim -C "+conf+" -be "+probe)
	}
	want = append(want, "rspamd --version", "rspamadm --version", "rspamadm configdump -j options",
		"systemctl show -p LoadState -p User -p CanReload rspamd.service",
		"systemctl show -p LoadState -p User -p CanReload exim.service")
	if !slices.Equal(run.calls, want) {
		t.Errorf("commands\n got %q\nwant %q", run.calls, want)
	}
}

// When every probe fails, nothing reads as root and CheckHost reports only
// temporary problems: a broken probe must never remove an installed
// integration.
func TestCollectFailedProbesStayTemporary(t *testing.T) {
	d := t.TempDir()
	write(t, filepath.Join(d, "spamddisable"), "")
	c := testCollector(d, &fakeRun{})
	c.lookPath = func(string) (string, error) { return "", errors.New("not found") }

	f := c.collect(context.Background(), "/csm-antispam-test-missing/s")

	s := f.Socket
	if s.RspamdUID != -1 || s.EximUID != -1 || s.EximGID != -1 || s.PeerUID != -1 || !s.Missing {
		t.Errorf("socket %+v", s)
	}
	if f.SystemFilter != "" || f.SystemFilterErr != nil || f.GeneratedErr == nil || f.LocalErr != nil || f.SystemdRunErr == nil {
		t.Errorf("facts %+v", f)
	}
	problems := antispam.CheckHost(f)
	if len(problems) == 0 {
		t.Fatal("no problems on a host where every probe failed")
	}
	for _, p := range problems {
		if p.Severity != antispam.Temporary {
			t.Errorf("%s is %d (%s), want temporary", p.Code, p.Severity, p.Detail)
		}
	}
}

func TestServiceUser(t *testing.T) {
	c := testCollector(t.TempDir(), &fakeRun{})
	for _, tc := range []struct {
		show antispam.CommandResult
		want int
	}{
		{antispam.CommandResult{Stdout: "User=_rspamd\nLoadState=loaded\n"}, 979},
		{antispam.CommandResult{Stdout: "User=\nLoadState=loaded\n"}, 0},
		{antispam.CommandResult{Stdout: "User=1500\nLoadState=loaded\n"}, 1500},
		{antispam.CommandResult{Stdout: "User=nosuch\nLoadState=loaded\n"}, -1},
		{antispam.CommandResult{Stdout: "User=\nLoadState=not-found\n"}, -1},
		{antispam.CommandResult{Stdout: "User=_rspamd\nLoadState=loaded\n", Err: errors.New("boom")}, -1},
	} {
		if got := c.serviceUser(tc.show); got != tc.want {
			t.Errorf("serviceUser(%q, %v) = %d, want %d", tc.show.Stdout, tc.show.Err, got, tc.want)
		}
	}
}

func TestRunCommandCapturesStreams(t *testing.T) {
	r := runCommand(context.Background(), "sh", "-c", "echo out; echo err >&2; exit 3")
	if r.Stdout != "out\n" || r.Stderr != "err\n" || r.Err == nil {
		t.Fatalf("got %+v", r)
	}
	if r := runCommand(context.Background(), "true"); r.Err != nil {
		t.Fatalf("true: %v", r.Err)
	}
}

func TestRunCommandStopsAtDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	r := runCommand(ctx, "sleep", "5")
	if !errors.Is(r.Err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", r.Err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("took %s", elapsed)
	}
}
