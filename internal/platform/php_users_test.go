package platform

import (
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func writeRootFile(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fakeProc lays out the two procfs entries the detector reads.
func fakeProc(t *testing.T, root string, pid int, exe string, uid int) {
	t.Helper()
	dir := filepath.Join(root, "proc", strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
	u := strconv.Itoa(uid)
	writeRootFile(t, root, filepath.Join("proc", strconv.Itoa(pid), "status"), "Name:\tx\nUid:\t"+u+"\t"+u+"\t"+u+"\t"+u+"\n")
}

const testPasswd = "root:x:0:0::/root:/bin/bash\n" +
	"www-data:x:33:33::/var/www:/usr/sbin/nologin\n" +
	"nginx:x:996:996::/var/lib/nginx:/sbin/nologin\n" +
	"apache:x:48:48::/usr/share/httpd:/sbin/nologin\n" +
	"site1:x:1001:1001::/home/site1:/bin/bash\n"

// Tenant code runs as whatever a PHP-FPM pool, a running PHP or CGI worker,
// or Apache's own PHP or CGI module names; setup must know each such user.
func TestPHPRuntimeUsers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, root string)
		want  map[string]string
	}{
		{"debian pools", func(t *testing.T, root string) {
			writeRootFile(t, root, "etc/php/8.2/fpm/pool.d/www.conf", "[www]\nuser = www-data\ngroup = www-data\n")
			writeRootFile(t, root, "etc/php/8.2/fpm/pool.d/site1.conf", "; site pool\n[site1]\nuser = $pool ; per site\n")
			writeRootFile(t, root, "etc/php/8.2/fpm/pool.d/off.conf", "[off]\n;user = nginx\n")
		}, map[string]string{"www-data": "PHP-FPM pool www", "site1": "PHP-FPM pool site1"}},
		{"rhel pool", func(t *testing.T, root string) {
			writeRootFile(t, root, "etc/php-fpm.d/www.conf", "[www]\nuser = \"apache\"\n")
		}, map[string]string{"apache": "PHP-FPM pool www"}},
		{"running workers", func(t *testing.T, root string) {
			fakeProc(t, root, 100, "/usr/sbin/php-fpm8.2", 0)
			fakeProc(t, root, 101, "/usr/sbin/php-fpm8.2", 996)
			fakeProc(t, root, 102, "/usr/sbin/fcgiwrap", 33)
			fakeProc(t, root, 103, "/usr/bin/php8.2", 1001)
			fakeProc(t, root, 104, "/usr/local/lsws/fcgi-bin/lsphp", 4242)
		}, map[string]string{"nginx": "a running php-fpm8.2 process", "www-data": "a running fcgiwrap process", "uid 4242": "a running lsphp process"}},
		{"debian apache modules", func(t *testing.T, root string) {
			writeRootFile(t, root, "etc/apache2/mods-enabled/php8.2.load", "LoadModule php_module /usr/lib/apache2/modules/libphp8.2.so\n")
			writeRootFile(t, root, "etc/apache2/envvars", "export APACHE_RUN_USER=www-data\n")
		}, map[string]string{"www-data": "Apache's PHP module"}},
		{"debian apache cgi", func(t *testing.T, root string) {
			writeRootFile(t, root, "etc/apache2/mods-enabled/cgid.load", "LoadModule cgid_module /usr/lib/apache2/modules/mod_cgid.so\n")
		}, map[string]string{"www-data": "Apache's CGI module"}},
		{"rhel apache modules", func(t *testing.T, root string) {
			writeRootFile(t, root, "etc/httpd/conf/httpd.conf", "User apache\nGroup apache\n")
			writeRootFile(t, root, "etc/httpd/conf.modules.d/01-cgi.conf", "<IfModule mpm_event_module>\n   #LoadModule cgid_module modules/mod_cgid.so\n</IfModule>\n")
			writeRootFile(t, root, "etc/httpd/conf.modules.d/15-php.conf", "LoadModule php_module modules/libphp.so\n")
		}, map[string]string{"apache": "Apache's PHP module"}},
		{"rhel apache cgi", func(t *testing.T, root string) {
			writeRootFile(t, root, "etc/httpd/conf.modules.d/01-cgi.conf", "<IfModule mpm_event_module>\n   LoadModule cgid_module modules/mod_cgid.so\n</IfModule>\n")
		}, map[string]string{"apache": "Apache's CGI module"}},
		{"nothing", func(*testing.T, string) {}, map[string]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeRootFile(t, root, "etc/passwd", testPasswd)
			tc.setup(t, root)
			if got := phpRuntimeUsers(root); !maps.Equal(got, tc.want) {
				t.Fatalf("users = %v, want %v", got, tc.want)
			}
		})
	}
}
