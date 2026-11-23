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
