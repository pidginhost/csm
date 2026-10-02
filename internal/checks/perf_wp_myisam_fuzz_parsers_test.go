package checks

import (
	"net"
	"strings"
	"testing"
)

func FuzzParseWPMyISAMConfig(f *testing.F) {
	f.Add(wpConfigFor("example_wp", "localhost", "wp_"))
	f.Add(wpConfigFor("example_wp", "localhost", ""))
	f.Add("<?php\xff")
	f.Add("<?php\n$table_prefix = getenv('PREFIX');")
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 64*1024 {
			return
		}
		creds, complete := parseWPMyISAMConfig([]byte(body))
		if complete && (creds.dbName == "" || creds.dbHost == "" ||
			(creds.tablePrefix != "" && !validTablePrefix.MatchString(creds.tablePrefix))) {
			t.Fatal("complete configuration has an unresolved scope")
		}
	})
}

func FuzzWPMyISAMDBHost(f *testing.F) {
	for _, host := range []string{"localhost", "localhost:3306:/run/mysql.sock", "[::1]:3306", "192.0.2.10", "[2001:db8::10]:3307", "db.example.com"} {
		f.Add(host)
	}
	f.Fuzz(func(t *testing.T, host string) {
		name, port, socket, ok := wpMyISAMDBHost(host)
		if !ok {
			if wpDBHostIsLocal(host) {
				t.Fatal("invalid endpoint classified as local")
			}
			return
		}
		if port == 0 || port > 65535 || (socket != "" && !strings.HasPrefix(socket, "/")) {
			t.Fatal("parsed endpoint has invalid port or socket")
		}
		if wpDBHostIsLocal(host) && name != "localhost" && net.ParseIP(name) == nil {
			t.Fatal("unverified hostname classified as local")
		}
	})
}
