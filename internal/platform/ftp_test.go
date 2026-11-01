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
	} {
		t.Run(tc.name, func(t *testing.T) {
			withMTAProbes(t, tc.onPath, tc.present)
			if got := FTPServerInstalled(); got != tc.want {
				t.Errorf("FTPServerInstalled() = %v, want %v", got, tc.want)
			}
		})
	}
}
