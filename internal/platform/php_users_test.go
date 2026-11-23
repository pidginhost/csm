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
		want  map[uint32]string
	}{
		{"debian pools", func(t *testing.T, root string) {
			writeRootFile(t, root, "etc/php/8.2/fpm/pool.d/www.conf", "[www]\nuser = www-data\ngroup = www-data\n")
			writeRootFile(t, root, "etc/php/8.2/fpm/pool.d/site1.conf", "; site pool\n[site1]\nuser = $pool ; per site\n")
			writeRootFile(t, root, "etc/php/8.2/fpm/pool.d/off.conf", "[off]\n;user = nginx\n")
		}, map[uint32]string{33: "PHP-FPM pool www", 1001: "PHP-FPM pool site1"}},
		{"rhel pool", func(t *testing.T, root string) {
			writeRootFile(t, root, "etc/php-fpm.d/www.conf", "[www]\nuser = \"apache\"\n")
		}, map[uint32]string{48: "PHP-FPM pool www"}},
		{"running workers", func(t *testing.T, root string) {
			fakeProc(t, root, 100, "/usr/sbin/php-fpm8.2", 0)
			writeRootFile(t, root, "proc/100/cmdline", "php-fpm: master process (/etc/php-fpm.conf)\x00")
			fakeProc(t, root, 101, "/usr/sbin/php-fpm8.2", 996)
			fakeProc(t, root, 102, "/usr/sbin/fcgiwrap", 33)
			fakeProc(t, root, 103, "/usr/bin/php8.2", 1001)
			fakeProc(t, root, 104, "/usr/local/lsws/fcgi-bin/lsphp", 4242)
		}, map[uint32]string{996: "a running php-fpm8.2 process", 33: "a running fcgiwrap process", 4242: "a running lsphp process"}},
		{"debian apache modules", func(t *testing.T, root string) {
			writeRootFile(t, root, "etc/apache2/mods-enabled/php8.2.load", "LoadModule php_module /usr/lib/apache2/modules/libphp8.2.so\n")
			writeRootFile(t, root, "etc/apache2/envvars", "export APACHE_RUN_USER=www-data\n")
		}, map[uint32]string{33: "Apache's PHP module"}},
		{"debian apache cgi", func(t *testing.T, root string) {
			writeRootFile(t, root, "etc/apache2/mods-enabled/cgid.load", "LoadModule cgid_module /usr/lib/apache2/modules/mod_cgid.so\n")
		}, map[uint32]string{33: "Apache's CGI module"}},
		{"rhel apache modules", func(t *testing.T, root string) {
			writeRootFile(t, root, "etc/httpd/conf/httpd.conf", "User apache\nGroup apache\n")
			writeRootFile(t, root, "etc/httpd/conf.modules.d/01-cgi.conf", "<IfModule mpm_event_module>\n   #LoadModule cgid_module modules/mod_cgid.so\n</IfModule>\n")
			writeRootFile(t, root, "etc/httpd/conf.modules.d/15-php.conf", "LoadModule php_module modules/libphp.so\n")
		}, map[uint32]string{48: "Apache's PHP module"}},
		{"rhel apache cgi", func(t *testing.T, root string) {
			writeRootFile(t, root, "etc/httpd/conf.modules.d/01-cgi.conf", "<IfModule mpm_event_module>\n   LoadModule cgid_module modules/mod_cgid.so\n</IfModule>\n")
		}, map[uint32]string{48: "Apache's CGI module"}},
		{"nothing", func(*testing.T, string) {}, map[uint32]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeRootFile(t, root, "etc/passwd", testPasswd)
			if err := os.MkdirAll(filepath.Join(root, "proc"), 0o755); err != nil {
				t.Fatal(err)
			}
			tc.setup(t, root)
			if got, err := phpRuntimeUsers(root); err != nil || !maps.Equal(got, tc.want) {
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("users = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPHPRuntimeUsersRegression(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		exe   string
		uid   int
		want  uint32
	}{
		{"section comment", map[string]string{"etc/php-fpm.d/www.conf": "[www] ; web pool\nuser = www-data\n"}, "", 0, 33},
		{"included pool", map[string]string{"etc/php-fpm.conf": "[global]\ninclude = /srv/pools/*.inc\n", "srv/pools/www.inc": "[www]\nuser = www-data\n"}, "", 0, 33},
		{"included user", map[string]string{"etc/php-fpm.d/www.conf": "[www-data]\ninclude = /srv/$pool.inc\n", "srv/www-data.inc": "user = '$pool' ; shared\n"}, "", 0, 33},
		{"quoted semicolon", map[string]string{"etc/php-fpm.conf": "include = '/srv/pools;active/*.inc'\n", "srv/pools;active/www.inc": "[www]\nuser = www-data\n"}, "", 0, 33},
		{"directadmin pool", map[string]string{"usr/local/php83/etc/php-fpm.conf": "include = /usr/local/directadmin/data/users/*/php/php-fpm83.conf\n", "usr/local/directadmin/data/users/site1/php/php-fpm83.conf": "[www]\nuser = www-data\n"}, "", 0, 33},
		{"cpanel main pool", map[string]string{"opt/cpanel/ea-php83/root/etc/php-fpm.conf": "[www]\nuser = www-data\n"}, "", 0, 33},
		{"root CGI", nil, "/usr/bin/php-cgi", 0, 0},
		{"root FastCGI", nil, "/usr/sbin/fcgiwrap", 0, 0},
		{"root FPM worker", map[string]string{"proc/200/cmdline": "php-fpm: pool www\x00"}, "/usr/sbin/php-fpm8.2", 0, 0},
		{"nondumpable worker", map[string]string{"proc/200/comm": "php-fpm8.2\n", "proc/200/status": "Uid:\t33\t33\t33\t33\n"}, "", 0, 33},
		{"apache env comment", map[string]string{"etc/apache2/envvars": "export APACHE_RUN_USER=www-data # worker\n", "etc/apache2/mods-enabled/cgi.load": "LoadModule cgi_module modules/mod_cgi.so\n"}, "", 0, 33},
		{"cpanel apache", map[string]string{"etc/apache2/conf/httpd.conf": "User www-data\nLoadModule cgi_module modules/mod_cgi.so\n"}, "", 0, 33},
		{"directadmin apache", map[string]string{"usr/local/apache/conf/httpd.conf": "User www-data\nLoadModule php_module modules/libphp.so\n"}, "", 0, 33},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeRootFile(t, root, "etc/passwd", testPasswd)
			if err := os.MkdirAll(filepath.Join(root, "proc"), 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.exe != "" {
				fakeProc(t, root, 200, tc.exe, tc.uid)
			}
			for path, body := range tc.files {
				writeRootFile(t, root, path, body)
			}
			if got, err := phpRuntimeUsers(root); err != nil || got[tc.want] == "" {
				t.Fatalf("users = %v, err %v; missing UID %d", got, err, tc.want)
			}
		})
	}
}

func TestPHPRuntimeIdentityAndParsing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		files   map[string]string
		want    map[uint32]string
		wantErr bool
	}{
		{"numeric pool user", map[string]string{"etc/php-fpm.d/www.conf": "[www]\nuser = 33\n"}, map[uint32]string{33: "PHP-FPM pool www"}, false},
		{"uid alias", map[string]string{"etc/passwd": testPasswd + "web-alias:x:33:33::/srv:/bin/false\n", "etc/php-fpm.d/www.conf": "[www]\nuser = web-alias\n"}, map[uint32]string{33: "PHP-FPM pool www"}, false},
		{"quoted pool and global", map[string]string{"etc/php-fpm.d/www.conf": "[global] ; supervisor\n; user = root\n['www-data'] ; pool\nuser = '$pool' ; identity\n[global] ; global again\npid = /run/php-fpm.pid\n"}, map[uint32]string{33: "PHP-FPM pool www-data"}, false},
		{"pool names ignore case", map[string]string{"etc/php-fpm.conf": "[www]\nuser = www-data\n[WWW]\nuser = site1\n"}, map[uint32]string{1001: "PHP-FPM pool www"}, false},
		{"last user wins", map[string]string{"etc/php-fpm.conf": "include = /etc/php-fpm.d/www.conf\n", "etc/php-fpm.d/www.conf": "[www]\nuser = www-data\ninclude = /srv/user.inc\n", "srv/user.inc": "user = site1\n"}, map[uint32]string{1001: "PHP-FPM pool www"}, false},
		{"include per pool", map[string]string{"etc/php-fpm.conf": "[www-data]\ninclude = /srv/user.inc\n[site1]\ninclude = /srv/user.inc\n", "srv/user.inc": "user = $pool\n"}, map[uint32]string{33: "PHP-FPM pool www-data", 1001: "PHP-FPM pool site1"}, false},
		{"include cycle", map[string]string{"etc/php-fpm.conf": "include = /etc/php-fpm.conf\n"}, nil, true},
		{"unresolved environment", map[string]string{"etc/php-fpm.conf": "[www]\nuser = ${FPM_USER}\n"}, nil, true},
		{"relative include", map[string]string{"etc/php-fpm.conf": "include = etc/pools/*.conf\n"}, nil, true},
		{"malformed worker credentials", map[string]string{"proc/200/comm": "php-cgi\n", "proc/200/status": "Uid: missing\n"}, nil, true},
		{"worker fsuid", map[string]string{"proc/200/comm": "lsphp\n", "proc/200/status": "Uid:\t1001\t1001\t1001\t33\n"}, map[uint32]string{33: "a running lsphp process", 1001: "a running lsphp process"}, false},
		{"commented Apache module", map[string]string{"etc/apache2/mods-enabled/php.load": "# LoadModule php_module modules/libphp.so\n"}, map[uint32]string{}, false},
		{"Apache numeric user", map[string]string{"etc/httpd/conf/httpd.conf": "User #33\nLoadModule cgid_module modules/mod_cgid.so\n"}, map[uint32]string{33: "Apache's CGI module"}, false},
		{"Apache includes", map[string]string{"etc/httpd/conf/httpd.conf": "User www-data\nInclude /srv/modules/*.conf\n", "srv/modules/php.conf": "loadmodule php_module modules/libphp.so\n"}, map[uint32]string{33: "Apache's PHP module"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeRootFile(t, root, "etc/passwd", testPasswd)
			if err := os.Mkdir(filepath.Join(root, "proc"), 0o755); err != nil {
				t.Fatal(err)
			}
			for path, body := range tc.files {
				writeRootFile(t, root, path, body)
			}
			got, err := phpRuntimeUsers(root)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error %v", err, tc.wantErr)
			}
			if !tc.wantErr && !maps.Equal(got, tc.want) {
				t.Fatalf("users = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPHPRuntimeUsersReadErrors(t *testing.T) {
	root := t.TempDir()
	writeRootFile(t, root, "etc/passwd", testPasswd)
	if _, err := phpRuntimeUsers(root); err == nil {
		t.Fatal("missing procfs accepted as no PHP workers")
	}
	if err := os.Mkdir(filepath.Join(root, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc/php-fpm.conf"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := phpRuntimeUsers(root); err == nil {
		t.Fatal("unreadable config accepted as no PHP pools")
	}
}

func TestPHPRuntimeUsersDistributionAndPanelPaths(t *testing.T) {
	for _, path := range []string{
		"etc/php/8.4/fpm/php-fpm.conf", "etc/php-fpm.conf",
		"etc/opt/remi/php84/php-fpm.conf", "opt/remi/php84/root/etc/php-fpm.conf",
		"usr/local/etc/php-fpm.conf", "usr/local/php84/etc/php-fpm.conf",
		"opt/plesk/php/8.4/etc/php-fpm.conf", "opt/alt/php84/etc/php-fpm.conf",
		"opt/cpanel/ea-php84/root/etc/php-fpm.conf",
		"usr/local/directadmin/data/users/site1/php/php-fpm84.conf",
	} {
		t.Run(path, func(t *testing.T) {
			root := t.TempDir()
			writeRootFile(t, root, "etc/passwd", testPasswd)
			if err := os.Mkdir(filepath.Join(root, "proc"), 0o755); err != nil {
				t.Fatal(err)
			}
			writeRootFile(t, root, path, "[www]\nuser = www-data\n")
			got, err := phpRuntimeUsers(root)
			if err != nil || !maps.Equal(got, map[uint32]string{33: "PHP-FPM pool www"}) {
				t.Fatalf("users = %v, err %v", got, err)
			}
		})
	}
}
