package platform

import (
	"maps"
	"os"
	"path/filepath"
	"testing"
)

func TestPHPRuntimeUsersLiteSpeedIsolation(t *testing.T) {
	for _, tc := range []struct {
		name, config, exe, body string
		want                    map[uint32]string
		wantErr                 bool
	}{
		{name: "commented isolation", body: `<httpServerConfig><user>www-data</user><!-- <phpSuExec>1</phpSuExec> --></httpServerConfig>`, want: map[uint32]string{33: "LiteSpeed's PHP handler"}},
		{name: "nested user first", body: `<httpServerConfig><extProcessor><user>site1</user></extProcessor><user>www-data</user></httpServerConfig>`, want: map[uint32]string{33: "LiteSpeed's PHP handler"}},
		{name: "commented user first", body: `<httpServerConfig><!-- <user>site1</user> --><user>www-data</user></httpServerConfig>`, want: map[uint32]string{33: "LiteSpeed's PHP handler"}},
		{name: "nested isolation", body: `<httpServerConfig><user>www-data</user><virtualHost><phpSuExec>1</phpSuExec></virtualHost></httpServerConfig>`, wantErr: true},
		{name: "duplicate isolation", body: `<httpServerConfig><user>www-data</user><phpSuExec>1</phpSuExec><phpSuExec>0</phpSuExec></httpServerConfig>`, wantErr: true},
		{name: "malformed XML", body: `<httpServerConfig><user>www-data</user><phpSuExec>1</phpSuExec>`, wantErr: true},
		{name: "unknown root", body: `<virtualHost><user>www-data</user><phpSuExec>1</phpSuExec></virtualHost>`, wantErr: true},
		{name: "no server user", body: `<httpServerConfig><extProcessor><user>site1</user></extProcessor></httpServerConfig>`, wantErr: true},
		{name: "duplicate server user", body: `<httpServerConfig><user>site1</user><user>www-data</user></httpServerConfig>`, wantErr: true},
		{name: "unknown isolation", body: `<httpServerConfig><user>www-data</user><phpSuExec>3</phpSuExec></httpServerConfig>`, want: map[uint32]string{33: "LiteSpeed's PHP handler"}},
		{name: "OLS nested user", config: "usr/local/lsws/conf/httpd_config.conf", body: "user www-data\nextprocessor app {\n user site1\n}\n", want: map[uint32]string{33: "LiteSpeed's PHP handler"}},
		{name: "OLS comment", config: "usr/local/lsws/conf/httpd_config.conf", body: "user www-data # server\n", want: map[uint32]string{33: "LiteSpeed's PHP handler"}},
		{name: "OLS no user", config: "usr/local/lsws/conf/httpd_config.conf", body: "extprocessor app {\n user site1\n}\n", wantErr: true},
		{name: "OLS include", config: "usr/local/lsws/conf/httpd_config.conf", body: "user site1\ninclude /srv/server.conf\n", wantErr: true},
		{name: "OLS duplicate user", config: "usr/local/lsws/conf/httpd_config.conf", body: "user site1\nuser www-data\n", wantErr: true},
		{name: "OLS unclosed block", config: "usr/local/lsws/conf/httpd_config.conf", body: "user www-data\nextprocessor app {\n", wantErr: true},
		{name: "custom enterprise install", config: "opt/webserver/conf/httpd_config.xml", exe: "/opt/webserver/bin/lshttpd.6.3.7", body: `<httpServerConfig><user>www-data</user></httpServerConfig>`, want: map[uint32]string{33: "LiteSpeed's PHP handler"}},
		{name: "custom isolated install", config: "opt/webserver/conf/httpd_config.xml", exe: "/opt/webserver/bin/litespeed", body: `<httpServerConfig><user>www-data</user><phpSuExec>2</phpSuExec></httpServerConfig>`, want: map[uint32]string{}},
		{name: "custom OLS install", config: "srv/webserver/conf/httpd_config.conf", exe: "/srv/webserver/bin/openlitespeed", body: "user www-data\n", want: map[uint32]string{33: "LiteSpeed's PHP handler"}},
		{name: "missing custom config", exe: "/opt/webserver/bin/litespeed", wantErr: true},
		{name: "missing default config", exe: "/usr/local/lsws/bin/litespeed", wantErr: true},
		{name: "unreadable executable", config: "usr/local/lsws/conf/httpd_config.xml", body: `<httpServerConfig><phpSuExec>1</phpSuExec></httpServerConfig>`, exe: "unreadable", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeRootFile(t, root, "etc/passwd", testPasswd+"nobody:x:65534:65534::/:/sbin/nologin\n")
			if err := os.MkdirAll(filepath.Join(root, "proc"), 0755); err != nil {
				t.Fatal(err)
			}
			if tc.exe == "unreadable" {
				writeRootFile(t, root, "proc/200/comm", "litespeed\n")
				writeRootFile(t, root, "proc/200/status", "Name:\tlitespeed\nUid:\t0\t0\t0\t0\n")
			} else if tc.exe != "" {
				fakeProc(t, root, 200, tc.exe, 0)
			}
			if tc.body != "" {
				config := tc.config
				if config == "" {
					config = "usr/local/lsws/conf/httpd_config.xml"
				}
				writeRootFile(t, root, config, tc.body)
			}
			got, err := phpRuntimeUsers(root)
			if (err != nil) != tc.wantErr {
				t.Fatalf("users = %v, error = %v; want error %v", got, err, tc.wantErr)
			}
			if !tc.wantErr && !maps.Equal(got, tc.want) {
				t.Fatalf("users = %v; want %v", got, tc.want)
			}
		})
	}
}

func TestPHPRuntimeUsersLiteSpeedBothFormats(t *testing.T) {
	root := t.TempDir()
	writeRootFile(t, root, "etc/passwd", testPasswd)
	if err := os.Mkdir(filepath.Join(root, "proc"), 0755); err != nil {
		t.Fatal(err)
	}
	writeRootFile(t, root, "usr/local/lsws/conf/httpd_config.xml", `<httpServerConfig><phpSuExec>1</phpSuExec></httpServerConfig>`)
	writeRootFile(t, root, "usr/local/lsws/conf/httpd_config.conf", "user www-data\n")
	got, err := phpRuntimeUsers(root)
	if err != nil || !maps.Equal(got, map[uint32]string{33: "LiteSpeed's PHP handler"}) {
		t.Fatalf("users = %v, error = %v; an Enterprise configuration must not hide OpenLiteSpeed's shared user", got, err)
	}
}

func TestPHPRuntimeUsersLiteSpeedMissingConfiguration(t *testing.T) {
	root := t.TempDir()
	writeRootFile(t, root, "etc/passwd", testPasswd+"nobody:x:65534:65534::/:/sbin/nologin\n")
	if err := os.Mkdir(filepath.Join(root, "proc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "usr/local/lsws/conf"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := phpRuntimeUsers(root); err == nil {
		t.Fatal("a missing server configuration must not guess nobody as the server user")
	}
}

func TestLiteSpeedDetectedInstallation(t *testing.T) {
	for _, tc := range []struct {
		name, binary, config string
		wantErr              bool
	}{
		{"custom binary", "/opt/webserver/bin/lshttpd", "opt/webserver/conf/httpd_config.xml", false},
		{"missing custom configuration", "/opt/webserver/bin/litespeed", "", true},
		{"unknown server location", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.config != "" {
				writeRootFile(t, root, tc.config, `<httpServerConfig><user>www-data</user></httpServerConfig>`)
			}
			var users []string
			err := liteSpeedInstalledUsers(root, Info{WebServer: WSLiteSpeed, LiteSpeedBinary: tc.binary}, func(user, source string) error {
				users = append(users, user)
				return nil
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v; want error %v", err, tc.wantErr)
			}
			if !tc.wantErr && (len(users) != 1 || users[0] != "www-data") {
				t.Fatalf("users = %v; want [www-data]", users)
			}
		})
	}
}

func TestPHPRuntimeUsersStandaloneLSPHP(t *testing.T) {
	root := t.TempDir()
	writeRootFile(t, root, "etc/passwd", testPasswd)
	writeRootFile(t, root, "usr/local/lsws/lsphp83/bin/lsphp", "")
	if err := os.Mkdir(filepath.Join(root, "proc"), 0755); err != nil {
		t.Fatal(err)
	}
	got, err := phpRuntimeUsers(root)
	if err != nil || len(got) != 0 {
		t.Fatalf("users = %v, error = %v; an interpreter package alone is not a LiteSpeed server", got, err)
	}
}

// Any local user can give a process LiteSpeed's name, as a copied binary, a
// hard link to a setuid program or a zombie. Only a process whose real
// UID is root locates a server installation; a user's own copy and its files
// prove nothing and must not stop the inspection.
func TestPHPRuntimeUsersIgnoresUserLiteSpeedProcess(t *testing.T) {
	for _, tc := range []struct{ name, exe, config, body string }{
		{"missing configuration", "/home/site1/bin/lshttpd", "", ""},
		{"user configuration", "/home/site1/bin/litespeed", "home/site1/conf/httpd_config.xml", "<httpServerConfig><user>root</user></httpServerConfig>"},
		{"setuid program", "/home/site1/bin/lshttpd", "", ""},
		{"exited process", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeRootFile(t, root, "etc/passwd", testPasswd)
			switch {
			case tc.exe == "":
				writeRootFile(t, root, "proc/300/comm", "lshttpd\n")
				writeRootFile(t, root, "proc/300/status", "Name:\tlshttpd\nState:\tZ (zombie)\nUid:\t1001\t1001\t1001\t1001\n")
			case tc.name == "setuid program":
				// Effective UID root, real UID the user's.
				fakeProc(t, root, 300, tc.exe, 1001)
				writeRootFile(t, root, "proc/300/status", "Name:\tlshttpd\nUid:\t1001\t0\t0\t0\n")
			default:
				fakeProc(t, root, 300, tc.exe, 1001)
			}
			if tc.config != "" {
				writeRootFile(t, root, tc.config, tc.body)
			}
			got, err := phpRuntimeUsers(root)
			if err != nil || len(got) != 0 {
				t.Fatalf("users = %v, error = %v; a user's process named like LiteSpeed located a server", got, err)
			}
		})
	}
}
