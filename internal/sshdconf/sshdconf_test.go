package sshdconf

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// writeConfig writes content to dir/name and returns the full path.
func writeConfig(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestListenPortsCollectsEveryPortDirective(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "sshd_config", "Port 22\nPort 2222\nPort 2223\n")

	got := Parse(OSFS{}, path).ListenPorts()
	want := []int{22, 2222, 2223}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListenPorts() = %v, want %v (sshd accepts repeated Port lines)", got, want)
	}
}

func TestListenPortsDefaultsTo22WhenUnset(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "sshd_config", "PermitRootLogin no\n")

	got := Parse(OSFS{}, path).ListenPorts()
	if !reflect.DeepEqual(got, []int{22}) {
		t.Errorf("ListenPorts() = %v, want [22]", got)
	}
}

func TestListenPortsFromIncludedDropIn(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "sshd_config.d/50-port.conf", "Port 2222\n")
	path := writeConfig(t, dir, "sshd_config", "Include "+filepath.Join(dir, "sshd_config.d", "*.conf")+"\n")

	got := Parse(OSFS{}, path).ListenPorts()
	if !reflect.DeepEqual(got, []int{2222}) {
		t.Errorf("ListenPorts() = %v, want [2222] (Debian keeps the real Port in a drop-in)", got)
	}
}

func TestIncludeRelativePatternResolvesAgainstConfigDir(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "sshd_config.d/50-port.conf", "Port 2244\n")
	path := writeConfig(t, dir, "sshd_config", "Include sshd_config.d/*.conf\n")

	got := Parse(OSFS{}, path).ListenPorts()
	if !reflect.DeepEqual(got, []int{2244}) {
		t.Errorf("ListenPorts() = %v, want [2244]", got)
	}
}

// A drop-in Port does not shadow the one in the main file: sshd binds both,
// which is exactly what a first-match-wins parser used to hide.
func TestIncludedAndInlinePortsBothBind(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "50-custom.conf", "Port 3333\n")
	path := writeConfig(t, dir, "sshd_config", "Include "+filepath.Join(dir, "*.conf")+"\nPort 4444\n")

	got := Parse(OSFS{}, path).ListenPorts()
	want := []int{3333, 4444}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListenPorts() = %v, want %v", got, want)
	}
}

func TestIncludeAcceptsMultiplePatternsOnOneLine(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "a/one.conf", "Port 2201\n")
	writeConfig(t, dir, "b/two.conf", "Port 2202\n")
	path := writeConfig(t, dir, "sshd_config", "Include a/*.conf b/*.conf\n")

	got := Parse(OSFS{}, path).ListenPorts()
	want := []int{2201, 2202}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListenPorts() = %v, want %v", got, want)
	}
}

func TestIncludeAcceptsQuotedPatternWithSpaces(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "drop ins/50-port.conf", "Port 2205\n")
	path := writeConfig(t, dir, "sshd_config", "Include \"drop ins/*.conf\" # local drop-ins\n")

	got := Parse(OSFS{}, path).ListenPorts()
	if !reflect.DeepEqual(got, []int{2205}) {
		t.Errorf("ListenPorts() = %v, want [2205]", got)
	}
}

func TestSelfIncludingConfigTerminates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	writeConfig(t, dir, "sshd_config", "Port 2222\nInclude "+path+"\n")

	got := Parse(OSFS{}, path).ListenPorts()
	if !reflect.DeepEqual(got, []int{2222}) {
		t.Errorf("ListenPorts() = %v, want [2222]", got)
	}
}

type countingFS struct {
	opens int
}

func (f *countingFS) Open(name string) (*os.File, error) {
	f.opens++
	return OSFS{}.Open(name)
}

func (*countingFS) Glob(pattern string) ([]string, error) {
	return OSFS{}.Glob(pattern)
}

func TestIncludeCyclesReadEachFileOnce(t *testing.T) {
	t.Run("glob matches parent", func(t *testing.T) {
		dir := t.TempDir()
		path := writeConfig(t, dir, "root.conf", "Port 2222\nInclude *.conf\n")
		fsys := &countingFS{}

		got := Parse(fsys, path).ListenPorts()
		if !reflect.DeepEqual(got, []int{2222}) {
			t.Errorf("ListenPorts() = %v, want [2222]", got)
		}
		if fsys.opens != 1 {
			t.Errorf("Open called %d times, want 1 for a self-matching glob", fsys.opens)
		}
	})

	t.Run("mutual include", func(t *testing.T) {
		dir := t.TempDir()
		aPath := filepath.Join(dir, "a.conf")
		bPath := filepath.Join(dir, "b.conf")
		writeConfig(t, dir, "a.conf", "Port 2201\nInclude "+bPath+"\n")
		writeConfig(t, dir, "b.conf", "Port 2202\nInclude "+aPath+"\n")
		fsys := &countingFS{}

		got := Parse(fsys, aPath).ListenPorts()
		want := []int{2201, 2202}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ListenPorts() = %v, want %v", got, want)
		}
		if fsys.opens != 2 {
			t.Errorf("Open called %d times, want once per file", fsys.opens)
		}
	})
}

func TestPortInsideMatchBlockIgnored(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "sshd_config", "Port 2222\nMatch User admin\nPort 2323\n")

	got := Parse(OSFS{}, path).ListenPorts()
	if !reflect.DeepEqual(got, []int{2222}) {
		t.Errorf("ListenPorts() = %v, want [2222] (Match-scoped directives are not global)", got)
	}
}

func TestPortAcceptsEqualsAndTabSeparators(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "sshd_config", "Port=2222\nPort\t2223\nPort = 2224\n")

	got := Parse(OSFS{}, path).ListenPorts()
	want := []int{2222, 2223, 2224}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListenPorts() = %v, want %v", got, want)
	}
}

func TestArgumentsAcceptQuotesEscapesAndInlineComments(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "sshd_config",
		"Port \"2222\" # alternate port\nPasswordAuthentication 'NO' # keys only\nPermitRootLogin prohibit\\-password\n")

	cfg := Parse(OSFS{}, path)
	if got := cfg.ListenPorts(); !reflect.DeepEqual(got, []int{2222}) {
		t.Errorf("ListenPorts() = %v, want [2222]", got)
	}
	if got := cfg.Value("passwordauthentication"); got != "no" {
		t.Errorf("Value(passwordauthentication) = %q, want no", got)
	}
	if got := cfg.Value("permitrootlogin"); got != `prohibit\-password` {
		t.Errorf("Value(permitrootlogin) = %q, want the unrecognised escape preserved", got)
	}
}

func TestPortAcceptsServiceName(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "sshd_config", "Port ssh\n")

	got := Parse(OSFS{}, path).ListenPorts()
	if !reflect.DeepEqual(got, []int{22}) {
		t.Errorf("ListenPorts() = %v, want [22] for the ssh service", got)
	}
}

func TestPortRejectsOutOfRangeAndNonNumeric(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "sshd_config", "Port abc\nPort 0\nPort 70000\nPort -1\nPort 2222\n")

	got := Parse(OSFS{}, path).ListenPorts()
	if !reflect.DeepEqual(got, []int{2222}) {
		t.Errorf("ListenPorts() = %v, want [2222]", got)
	}
}

func TestListenAddressWithPortAddsThatPort(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "sshd_config",
		"Port 2222\nListenAddress 0.0.0.0\nListenAddress 192.0.2.1:2022\nListenAddress [2001:db8::1]:2023\n")

	got := Parse(OSFS{}, path).ListenPorts()
	want := []int{2022, 2023, 2222}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListenPorts() = %v, want %v", got, want)
	}
}

// Every ListenAddress carrying its own port means Port never gets bound:
// sshd only applies Port to ListenAddress entries that omit one.
func TestListenAddressPortsOverridePortDirective(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "sshd_config", "Port 2222\nListenAddress 192.0.2.1:2022\n")

	got := Parse(OSFS{}, path).ListenPorts()
	if !reflect.DeepEqual(got, []int{2022}) {
		t.Errorf("ListenPorts() = %v, want [2022]", got)
	}
}

func TestListenAddressWithoutPortKeepsDefault(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "sshd_config", "ListenAddress 0.0.0.0\nListenAddress ::\n")

	got := Parse(OSFS{}, path).ListenPorts()
	if !reflect.DeepEqual(got, []int{22}) {
		t.Errorf("ListenPorts() = %v, want [22]", got)
	}
}

func TestRemoteListenPortsHonorAddressFamily(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name    string
		content string
		wantV4  []int
		wantV6  []int
	}{
		{name: "default is dual stack", content: "Port 2222\n", wantV4: []int{2222}, wantV6: []int{2222}},
		{name: "IPv4 only", content: "AddressFamily inet\nPort 2222\n", wantV4: []int{2222}, wantV6: []int{}},
		{name: "IPv6 only", content: "AddressFamily inet6\nPort 2222\n", wantV4: []int{}, wantV6: []int{2222}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, dir, strings.ReplaceAll(tt.name, " ", "-")+".conf", tt.content)
			gotV4, gotV6 := Parse(OSFS{}, path).RemoteListenPorts()
			if !reflect.DeepEqual(gotV4, tt.wantV4) {
				t.Errorf("IPv4 ports = %v, want %v", gotV4, tt.wantV4)
			}
			if !reflect.DeepEqual(gotV6, tt.wantV6) {
				t.Errorf("IPv6 ports = %v, want %v", gotV6, tt.wantV6)
			}
		})
	}
}

func TestRemoteListenPortsFollowAddressesAndIgnoreLoopback(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "sshd_config", strings.Join([]string{
		"Port 2222",
		"ListenAddress 192.0.2.10",
		"ListenAddress 198.51.100.10:2204",
		"ListenAddress 127.0.0.1:2205",
		"ListenAddress localhost:2208",
		"ListenAddress 2001:db8::10",
		"ListenAddress [2001:db8::11]:2206",
		"ListenAddress [::1]:2207",
	}, "\n")+"\n")

	gotV4, gotV6 := Parse(OSFS{}, path).RemoteListenPorts()
	if want := []int{2204, 2222}; !reflect.DeepEqual(gotV4, want) {
		t.Errorf("IPv4 ports = %v, want %v", gotV4, want)
	}
	if want := []int{2206, 2222}; !reflect.DeepEqual(gotV6, want) {
		t.Errorf("IPv6 ports = %v, want %v", gotV6, want)
	}
}

func TestPresentReportsWhetherRootFileWasRead(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "sshd_config", "Port 2222\n")
	if !Parse(OSFS{}, path).Present() {
		t.Error("Present() = false for a readable config")
	}

	missing := Parse(OSFS{}, filepath.Join(dir, "absent"))
	if missing.Present() {
		t.Error("Present() = true for a missing config")
	}
	if !reflect.DeepEqual(missing.ListenPorts(), []int{22}) {
		t.Errorf("missing config ListenPorts() = %v, want the compiled default [22]", missing.ListenPorts())
	}
}

func TestValueIsFirstMatchWinsAndLowercased(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "sshd_config",
		"PasswordAuthentication NO\nPasswordAuthentication yes\nPermitRootLogin Prohibit-Password\n")

	cfg := Parse(OSFS{}, path)
	if got := cfg.Value("passwordauthentication"); got != "no" {
		t.Errorf("Value(passwordauthentication) = %q, want no", got)
	}
	if got := cfg.Value("PermitRootLogin"); got != "prohibit-password" {
		t.Errorf("Value(PermitRootLogin) = %q, want prohibit-password", got)
	}
}

func TestValueFallsBackToCompiledDefault(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "sshd_config", "Port 2222\n")

	cfg := Parse(OSFS{}, path)
	if got := cfg.Value("passwordauthentication"); got != "yes" {
		t.Errorf("Value(passwordauthentication) = %q, want the OpenSSH default yes", got)
	}
	if got := cfg.Value("x11forwarding"); got != "no" {
		t.Errorf("Value(x11forwarding) = %q, want the OpenSSH default no", got)
	}
	if got := cfg.Value("clientaliveinterval"); got != "" {
		t.Errorf("Value(clientaliveinterval) = %q, want empty for a keyword with no shipped default", got)
	}
}

func TestValueIgnoresMatchBlockDirectives(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "sshd_config",
		"PasswordAuthentication no\nMatch Address 192.0.2.0/24\nPasswordAuthentication yes\nX11Forwarding yes\n")

	cfg := Parse(OSFS{}, path)
	if got := cfg.Value("passwordauthentication"); got != "no" {
		t.Errorf("Value(passwordauthentication) = %q, want no (global value, not the Match one)", got)
	}
	if got := cfg.Value("x11forwarding"); got != "no" {
		t.Errorf("Value(x11forwarding) = %q, want the default no; the Match value must not leak", got)
	}
}

// A second Match keyword ends the previous block but opens another one, so
// directives after it stay connection-scoped.
func TestConsecutiveMatchBlocksStayScoped(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "sshd_config",
		"Port 2222\nMatch User admin\nPermitRootLogin yes\nMatch Address 192.0.2.0/24\nX11Forwarding yes\n")

	cfg := Parse(OSFS{}, path)
	if got := cfg.Value("permitrootlogin"); got != "prohibit-password" {
		t.Errorf("Value(permitrootlogin) = %q, want the default; the Match value must not leak", got)
	}
	if got := cfg.Value("x11forwarding"); got != "no" {
		t.Errorf("Value(x11forwarding) = %q, want the default; the second Match block must stay scoped", got)
	}
}

func TestScalarKeywordAcceptsEqualsForm(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "sshd_config", "PermitRootLogin=no\nX11Forwarding\tyes\n")

	cfg := Parse(OSFS{}, path)
	if got := cfg.Value("permitrootlogin"); got != "no" {
		t.Errorf("Value(permitrootlogin) = %q, want no", got)
	}
	if got := cfg.Value("x11forwarding"); got != "yes" {
		t.Errorf("Value(x11forwarding) = %q, want yes", got)
	}
}

// A corrupt file must not be pulled into memory whole, and one over-long line
// must not hide the directives that follow it.
func TestOverlongLineIsBoundedAndKeepsParsing(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "sshd_config",
		"PermitRootLogin "+strings.Repeat("a", 4*maxLineBytes)+"\nPort 2222\n")

	cfg := Parse(OSFS{}, path)
	if got := len(cfg.Value("permitrootlogin")); got > maxLineBytes {
		t.Errorf("kept %d bytes of an over-long directive, want at most %d", got, maxLineBytes)
	}
	if got := cfg.ListenPorts(); !reflect.DeepEqual(got, []int{2222}) {
		t.Errorf("ListenPorts() = %v, want [2222]", got)
	}
}

func TestCommentsAndBlankLinesIgnored(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "sshd_config", "# Port 9999\n\n   \nPort 2222\n")

	got := Parse(OSFS{}, path).ListenPorts()
	if !reflect.DeepEqual(got, []int{2222}) {
		t.Errorf("ListenPorts() = %v, want [2222]", got)
	}
}

func TestLongLineDoesNotHideFollowingDirectives(t *testing.T) {
	dir := t.TempDir()
	content := "# " + strings.Repeat("x", 128*1024) + "\nPort 2222\n"
	path := writeConfig(t, dir, "sshd_config", content)

	got := Parse(OSFS{}, path).ListenPorts()
	if !reflect.DeepEqual(got, []int{2222}) {
		t.Errorf("ListenPorts() = %v, want [2222] after a long valid line", got)
	}
}

// fakeFS proves Parse drives every file access through the injected FS, which
// is what lets internal/checks keep its mock-driven tests.
type fakeFS struct {
	files map[string]string
	dir   string
	t     *testing.T
}

func (f fakeFS) Open(name string) (*os.File, error) {
	content, ok := f.files[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	path := filepath.Join(f.dir, filepath.Base(name))
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		f.t.Fatal(err)
	}
	return os.Open(path) // #nosec G304 -- test-controlled temp path
}

func (f fakeFS) Glob(string) ([]string, error) { return nil, nil }

func TestParseUsesInjectedFS(t *testing.T) {
	fs := fakeFS{
		files: map[string]string{"/etc/ssh/sshd_config": "Port 2222\nPermitRootLogin no\n"},
		dir:   t.TempDir(),
		t:     t,
	}

	cfg := Parse(fs, DefaultPath)
	if !cfg.Present() {
		t.Fatal("Present() = false, want true from the injected FS")
	}
	if !reflect.DeepEqual(cfg.ListenPorts(), []int{2222}) {
		t.Errorf("ListenPorts() = %v, want [2222]", cfg.ListenPorts())
	}
	if got := cfg.Value("permitrootlogin"); got != "no" {
		t.Errorf("Value(permitrootlogin) = %q, want no", got)
	}
}
