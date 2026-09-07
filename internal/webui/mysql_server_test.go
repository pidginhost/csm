package webui

import "testing"

// Memory was read via a hardcoded /var/run/mysqld/mysqld.pid. cPanel hosts run
// MariaDB, which writes /var/lib/mysql/<host>.pid, so the file was absent and
// the panel showed "n/a" for memory on exactly the platform CSM targets.
// Identifying the server from its own cmdline avoids guessing per-distro pid
// paths altogether.
func TestIsMySQLServerCmdline(t *testing.T) {
	tests := []struct {
		name    string
		cmdline string
		want    bool
	}{
		{"mariadb on cpanel", "/usr/sbin/mariadbd --basedir=/usr", true},
		{"mysqld", "/usr/sbin/mysqld --daemonize", true},
		{"mysqld bare", "mysqld", true},
		{"mariadbd bare", "mariadbd", true},

		// Wrappers and clients are not the server.
		{"mysqld_safe wrapper", "/bin/sh /usr/bin/mysqld_safe --datadir=/var/lib/mysql", false},
		{"mariadb client", "/usr/bin/mariadb -e SHOW STATUS", false},
		{"mysql client", "mysql -u root", false},
		{"backup tool", "/usr/bin/mariabackup --backup", false},
		{"empty", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isMySQLServerCmdline(tc.cmdline); got != tc.want {
				t.Errorf("isMySQLServerCmdline(%q) = %v, want %v", tc.cmdline, got, tc.want)
			}
		})
	}
}
