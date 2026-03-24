package checks

import "testing"

func TestIsWebshellName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"h4x0r.php", true},
		{"c99.php", true},
		{"shell.php", true},
		{"cmd.php", true},
		{"index.php", false},
		{"wp-config.php", false},
		{"style.css", false},
	}
	for _, tt := range tests {
		if got := isWebshellName(tt.name); got != tt.want {
			t.Errorf("isWebshellName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestIsSuspiciousPHPName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"shell.php", true},
		{"cmd.php", true},
		{"backdoor.php", true},
		{"upload.php", true},
		{"x7y2.php", true}, // short random
		{"ab1.php", true},  // short random with digit
		{"functions.php", false},
		{"wp-config.php", false},
		{"index.php", false},
		{"style.css", false},
		{"my-long-plugin-name.php", false},
	}
	for _, tt := range tests {
		if got := isSuspiciousPHPName(tt.name); got != tt.want {
			t.Errorf("isSuspiciousPHPName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestIsKnownSafeUpload(t *testing.T) {
	tests := []struct {
		path string
		name string
		want bool
	}{
		{"/home/user/public_html/wp-content/uploads/index.php", "index.php", true},
		{"/home/user/public_html/wp-content/uploads/redux/color.php", "color.php", true},
		{"/home/user/public_html/wp-content/uploads/mailchimp-for-wp/debug.php", "debug.php", true},
		{"/home/user/public_html/wp-content/uploads/evil.php", "evil.php", false},
		{"/home/user/public_html/wp-content/uploads/2024/shell.php", "shell.php", false},
	}
	for _, tt := range tests {
		if got := isKnownSafeUpload(tt.path, tt.name); got != tt.want {
			t.Errorf("isKnownSafeUpload(%q, %q) = %v, want %v", tt.path, tt.name, got, tt.want)
		}
	}
}
