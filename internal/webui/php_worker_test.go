package webui

import "testing"

// The collector matched only "lsphp", so it counted PHP workers on LiteSpeed
// hosts and nothing at all on Apache/EA4, where cPanel runs php-fpm. A host
// serving a dozen pools reported "No PHP processes", which reads as an idle
// server rather than a blind collector.
func TestIsPHPWorkerCmdline(t *testing.T) {
	tests := []struct {
		name    string
		cmdline string
		want    bool
	}{
		// LiteSpeed, the only form previously recognised.
		{"lsphp", "/usr/local/lsws/lsphp82/bin/lsphp", true},
		{"lsphp with args", "lsphp /usr/local/lsws/fcgi-bin/lsphp82", true},

		// cPanel EA4 php-fpm pool workers: one process per request slot,
		// running as the account user. These are the ones that matter.
		{"ea-php pool worker", "php-fpm: pool zsauto_ca", true},
		{"ea-php pool worker other", "php-fpm: pool griro-tabla-expandata_ro", true},

		// The master runs as root and is not a request worker; counting it
		// would attribute load to root on every host.
		{"php-fpm master", "php-fpm: master process (/opt/cpanel/ea-php84/root/etc/php-fpm.conf)", false},

		// Unrelated processes must not be counted.
		{"php cli", "/opt/cpanel/ea-php84/root/usr/bin/php -v", false},
		{"nginx", "nginx: worker process", false},
		{"empty", "", false},
		{"mentions php in a path only", "/usr/bin/grep php-fpm /etc/hosts", false},
		{"grep of worker title", "/usr/bin/grep php-fpm: pool example", false},
		{"master with pool text in config path", "php-fpm: master process (/etc/php-fpm: pool example.conf)", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPHPWorkerCmdline(tc.cmdline); got != tc.want {
				t.Errorf("isPHPWorkerCmdline(%q) = %v, want %v", tc.cmdline, got, tc.want)
			}
		})
	}
}
