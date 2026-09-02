package checks

import "testing"

// The upload-tree gate looked at every directory component of the absolute
// path except the first, so any "tmp", "files" or "cache" in the prefix
// above the web tree (a temp root, an account literally named tmp) made
// every .htaccess below it an upload-tree hit and disabled the sibling-PHP
// gate. Only components inside the account's web tree count.
func TestHtaccessInUploadTreeJudgesOnlyTheWebTree(t *testing.T) {
	withAccountHomeRoots(t, "/srv/vhosts", "/home")
	cases := []struct {
		path string
		want bool
	}{
		{"/private/tmp/csm-gotest/T/001/public_html/wp-content/plugins/x/.htaccess", false},
		{"/srv/vhosts/alice/httpdocs/tmp/.htaccess", true},
		{"/home/alice/public_html/wp-content/uploads/2026/.htaccess", true},
		{"/home/tmp/public_html/plugins/x/.htaccess", false},
		{"/home/alice/files/.htaccess", true},
		{"/var/www/html/cache/.htaccess", true},
	}
	for _, tc := range cases {
		if got := htaccessInUploadTree(tc.path); got != tc.want {
			t.Errorf("htaccessInUploadTree(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
