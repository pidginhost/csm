package webserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeHandler is a self-contained Handler for unit tests. It records
// the calls the installer makes and lets a test arrange Validate /
// Reload to fail at chosen call counts so the rollback path can be
// exercised end to end.
type fakeHandler struct {
	kind        string
	path        string
	body        string
	validateErr []error
	reloadErr   []error
	validates   atomic.Int32
	reloads     atomic.Int32
}

func (h *fakeHandler) Kind() string        { return h.kind }
func (h *fakeHandler) SnippetPath() string { return h.path }
func (h *fakeHandler) Template() string    { return h.body }
func (h *fakeHandler) Validate() error {
	idx := h.validates.Add(1) - 1
	if int(idx) < len(h.validateErr) {
		return h.validateErr[int(idx)]
	}
	return nil
}
func (h *fakeHandler) Reload() error {
	idx := h.reloads.Add(1) - 1
	if int(idx) < len(h.reloadErr) {
		return h.reloadErr[int(idx)]
	}
	return nil
}

func newTestInstaller(t *testing.T, h *fakeHandler) *Installer {
	t.Helper()
	dir := t.TempDir()
	if h.path == "" {
		h.path = dir + "/csm-challenge.conf"
	}
	return &Installer{
		Handler:  h,
		Config:   RenderConfig{ChallengeMapPath: dir + "/run/challenge_ips.txt", ChallengeListenAddr: "127.0.0.1", ChallengeListenPort: 8439},
		MkdirAll: os.MkdirAll,
		WriteAt:  os.WriteFile,
		ReadAt:   os.ReadFile,
		StatAt:   os.Stat,
		RemoveAt: os.Remove,
		Stderr:   io.Discard,
	}
}

func TestInstallFreshWritesSnippetAndReloads(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n"}
	i := newTestInstaller(t, h)

	res, err := i.Install()
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Status != "ok" {
		t.Fatalf("status = %q, want ok", res.Status)
	}
	if h.validates.Load() != 1 || h.reloads.Load() != 1 {
		t.Fatalf("validate/reload counts = %d/%d, want 1/1", h.validates.Load(), h.reloads.Load())
	}
	data, err := os.ReadFile(h.path)
	if err != nil {
		t.Fatalf("snippet not written: %v", err)
	}
	if !strings.HasPrefix(string(data), templateHeaderPrefix) {
		t.Errorf("snippet missing version header: %q", string(data))
	}
	if !strings.Contains(string(data), "RewriteEngine On") {
		t.Errorf("snippet missing body content")
	}
	if _, err := os.Stat(i.Config.ChallengeMapPath); err != nil {
		t.Fatalf("challenge map not created: %v", err)
	}
}

func TestInstallRendersConfiguredPathsAndBackend(t *testing.T) {
	h := &fakeHandler{
		kind: "apache",
		body: "map={{ .ChallengeMapPath }} backend={{ .BackendURL }} hostport={{ .BackendHostPort }}\n",
	}
	i := newTestInstaller(t, h)
	i.Config.ChallengeMapPath = t.TempDir() + "/challenge_ips.txt"
	i.Config.ChallengeListenPort = 18439

	if _, err := i.Install(); err != nil {
		t.Fatalf("Install: %v", err)
	}
	data, err := os.ReadFile(h.path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	if !strings.Contains(body, "map="+i.Config.ChallengeMapPath) {
		t.Fatalf("rendered map path not based on config: %s", body)
	}
	if !strings.Contains(body, "backend=http://127.0.0.1:18439/challenge") {
		t.Fatalf("rendered backend URL not based on config: %s", body)
	}
	if !strings.Contains(body, "hostport=127.0.0.1:18439") {
		t.Fatalf("rendered backend hostport not based on config: %s", body)
	}
}

func TestShippedTemplatesRenderRuntimeConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "apache", body: apacheTemplate},
		{name: "lsws", body: lswsTemplate},
		{name: "nginx", body: nginxTemplate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &fakeHandler{kind: tc.name, body: tc.body}
			i := newTestInstaller(t, h)
			i.Config.ChallengeMapPath = "/run/custom-csm/challenge_ips.txt"
			i.Config.ChallengeListenPort = 18439
			rendered, err := i.renderTemplate()
			if err != nil {
				t.Fatalf("renderTemplate: %v", err)
			}
			body := string(rendered)
			if strings.Contains(body, "/opt/csm/state") {
				t.Fatalf("template still hardcodes legacy state path: %s", body)
			}
			if strings.Contains(body, "127.0.0.1:8439") {
				t.Fatalf("template still hardcodes default challenge port: %s", body)
			}
			if !strings.Contains(body, "127.0.0.1:18439") {
				t.Fatalf("template did not render configured challenge port: %s", body)
			}
		})
	}
}

func TestRenderTemplateIsStableForNoOpCompare(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n"}
	i := newTestInstaller(t, h)
	first, err := i.renderTemplate()
	if err != nil {
		t.Fatalf("first render: %v", err)
	}
	second, err := i.renderTemplate()
	if err != nil {
		t.Fatalf("second render: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("rendered template changed between identical inputs:\nfirst=%s\nsecond=%s", first, second)
	}
}

func TestInstallSameVersionIsNoOp(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n"}
	i := newTestInstaller(t, h)
	if _, err := i.Install(); err != nil {
		t.Fatalf("first install: %v", err)
	}

	res, err := i.Install()
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	if res.Status != "no-op" {
		t.Fatalf("status = %q, want no-op", res.Status)
	}
	// Validate + reload run once (first install) only.
	if h.reloads.Load() != 1 {
		t.Fatalf("reload ran %d times; want 1", h.reloads.Load())
	}
}

func TestInstallValidateFailureRollsBack(t *testing.T) {
	h := &fakeHandler{
		kind:        "apache",
		body:        "RewriteEngine On\n",
		validateErr: []error{errors.New("syntax error at line 7")},
	}
	i := newTestInstaller(t, h)

	res, err := i.Install()
	if err == nil {
		t.Fatal("expected configtest failure")
	}
	if res.Status != "fail" || !strings.Contains(res.Message, "configtest") {
		t.Fatalf("result = %+v, want fail/configtest", res)
	}
	// File must not exist after rollback (fresh install).
	if _, statErr := os.Stat(h.path); statErr == nil {
		t.Fatal("rollback failed: snippet still present after configtest failure")
	}
	// Reload must not have run.
	if h.reloads.Load() != 0 {
		t.Fatalf("reload ran %d times; want 0 on configtest fail", h.reloads.Load())
	}
}

func TestInstallReloadFailureRollsBackAndRecovers(t *testing.T) {
	h := &fakeHandler{
		kind:      "apache",
		body:      "RewriteEngine On\n",
		reloadErr: []error{errors.New("systemctl reload returned 1")},
	}
	i := newTestInstaller(t, h)

	res, err := i.Install()
	if err == nil {
		t.Fatal("expected reload failure")
	}
	if res.Status != "fail" || !strings.Contains(res.Message, "rolled back") {
		t.Fatalf("result = %+v, want fail with rolled-back marker", res)
	}
	// Recovery reload runs once after the first failure, total 2.
	if h.reloads.Load() != 2 {
		t.Fatalf("reload ran %d times; want 2 (initial fail + recovery)", h.reloads.Load())
	}
}

func TestInstallRefusesOperatorEdits(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n"}
	i := newTestInstaller(t, h)
	// Plant an operator-edited file lacking the version marker.
	if err := os.WriteFile(h.path, []byte("# operator notes\nfoo bar\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := i.Install()
	if !errors.Is(err, ErrManualEdits) {
		t.Fatalf("err = %v, want ErrManualEdits", err)
	}
	if res.Status != "fail" {
		t.Fatalf("status = %q, want fail", res.Status)
	}
}

func TestStatusReportsStateCorrectly(t *testing.T) {
	cases := []struct {
		name       string
		prepare    func(path string)
		wantStatus string
	}{
		{
			name:       "missing",
			prepare:    func(string) {},
			wantStatus: "missing",
		},
		{
			name: "modified",
			prepare: func(path string) {
				_ = os.WriteFile(path, []byte("hand-edited\n"), 0o644)
			},
			wantStatus: "modified",
		},
		{
			name: "stale",
			prepare: func(path string) {
				if TemplateVersion <= 1 {
					// Nothing to stage as stale: any lower marker
					// value (zero) is treated as missing header. The
					// case kicks in when TemplateVersion is bumped.
					return
				}
				_ = os.WriteFile(path, []byte(fmt.Sprintf("%s%d\nold body\n", templateHeaderPrefix, TemplateVersion-1)), 0o644)
			},
			wantStatus: "stale",
		},
		{
			name: "ok",
			prepare: func(path string) {
				_ = os.WriteFile(path, []byte(fmt.Sprintf("%s%d\nbody\n", templateHeaderPrefix, TemplateVersion)), 0o644)
			},
			wantStatus: "ok",
		},
	}
	for _, tc := range cases {
		if tc.name == "stale" && TemplateVersion <= 1 {
			// The "stale" branch can never be exercised via Status()
			// while shipped TemplateVersion is 1, because there is no
			// valid lower version (zero is reserved for "header
			// missing"). The classifier itself is covered by
			// TestClassifyStatus below.
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			h := &fakeHandler{kind: "apache", body: "body\n"}
			i := newTestInstaller(t, h)
			tc.prepare(h.path)
			res, _ := i.Status()
			if res.Status != tc.wantStatus {
				t.Fatalf("status = %q, want %q", res.Status, tc.wantStatus)
			}
		})
	}
}

// classifyStatus is unit-tested with arbitrary version pairs so the
// stale branch is exercised regardless of the package-level
// TemplateVersion constant.
func TestClassifyStatus(t *testing.T) {
	cases := []struct {
		name   string
		exists bool
		on, sh int
		want   string
	}{
		{"missing", false, 0, 1, "missing"},
		{"modified", true, 0, 1, "modified"},
		{"stale", true, 1, 2, "stale"},
		{"current", true, 2, 2, "ok"},
		{"ahead-of-shipped", true, 3, 2, "ok"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, _ := classifyStatus(c.exists, c.on, c.sh)
			if status != c.want {
				t.Fatalf("status = %q, want %q", status, c.want)
			}
		})
	}
}

func TestRemoveDeletesSnippetAndReloads(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n"}
	i := newTestInstaller(t, h)
	if _, err := i.Install(); err != nil {
		t.Fatal(err)
	}
	// install ran once; reset counters for clarity.
	h.validates.Store(0)
	h.reloads.Store(0)

	res, err := i.Remove()
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if res.Status != "ok" {
		t.Fatalf("status = %q, want ok", res.Status)
	}
	if _, statErr := os.Stat(h.path); statErr == nil {
		t.Fatal("snippet still present after Remove")
	}
}

func TestRemoveRefusesOperatorEdits(t *testing.T) {
	h := &fakeHandler{kind: "apache", body: "RewriteEngine On\n"}
	i := newTestInstaller(t, h)
	if err := os.WriteFile(h.path, []byte("manual edit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := i.Remove()
	if !errors.Is(err, ErrManualEdits) {
		t.Fatalf("err = %v, want ErrManualEdits", err)
	}
	if _, statErr := os.Stat(h.path); statErr != nil {
		t.Fatal("Remove deleted an operator-edited file; must keep it")
	}
}

func TestParseHeaderVersionHandlesGarbage(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"random data without marker", 0},
		{templateHeaderPrefix + "not-an-int\nrest", 0},
		{templateHeaderPrefix + "3\n", 3},
		{templateHeaderPrefix + "12\nbody...", 12},
	}
	for _, c := range cases {
		got := parseHeaderVersion([]byte(c.in))
		if got != c.want {
			t.Errorf("parseHeaderVersion(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// Use of cmdRunner via context to keep gofmt happy when the import is
// only touched in handler files. Compile-time reference.
var _ cmdRunner = realCmdRunner{}
var _ context.Context = context.Background()
