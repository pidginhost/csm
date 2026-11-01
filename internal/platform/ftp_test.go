package platform

import "testing"

func TestFTPServerInstalled(t *testing.T) {
	for _, tc := range []struct {
		name            string
		onPath, present map[string]bool
		want            bool
	}{
		{"plain host", nil, nil, false},
		{"ftp clients only", map[string]bool{"ftp": true, "lftp": true}, nil, false},
		{"cpanel", nil, map[string]bool{"/usr/local/cpanel/version": true}, true},
		{"vsftpd on path", map[string]bool{"vsftpd": true}, nil, true},
		{"proftpd outside path", nil, map[string]bool{"/usr/sbin/proftpd": true}, true},
		{"pure-ftpd outside path", nil, map[string]bool{"/usr/sbin/pure-ftpd": true}, true},
		{"plesk proftpd on path", map[string]bool{"in.proftpd": true}, nil, true},
		{"plesk proftpd outside path", nil, map[string]bool{"/usr/sbin/in.proftpd": true}, true},
		{"pure-ftpd mysql on path", map[string]bool{"pure-ftpd-mysql": true}, nil, true},
		{"pure-ftpd mysql outside path", nil, map[string]bool{"/usr/sbin/pure-ftpd-mysql": true}, true},
		{"pure-ftpd postgresql on path", map[string]bool{"pure-ftpd-postgresql": true}, nil, true},
		{"pure-ftpd postgresql outside path", nil, map[string]bool{"/usr/sbin/pure-ftpd-postgresql": true}, true},
		{"pure-ftpd ldap on path", map[string]bool{"pure-ftpd-ldap": true}, nil, true},
		{"pure-ftpd ldap outside path", nil, map[string]bool{"/usr/sbin/pure-ftpd-ldap": true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withMTAProbes(t, tc.onPath, tc.present)
			if got := FTPServerInstalled(); got != tc.want {
				t.Errorf("FTPServerInstalled() = %v, want %v", got, tc.want)
			}
		})
	}
}
