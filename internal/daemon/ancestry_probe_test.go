package daemon

import "testing"

func TestIsPackageManagerCommRecognizesTruncatedUnattendedUpgrade(t *testing.T) {
	tests := []struct {
		name string
		comm string
		want bool
	}{
		{name: "exact package manager", comm: "apt-get", want: true},
		{name: "truncated unattended upgrade", comm: "unattended-upgr", want: true},
		{name: "prefix only", comm: "unattended-", want: false},
		{name: "similar non package name", comm: "unattendedx", want: false},
		{name: "generic shell", comm: "sh", want: false},
		{name: "similar rpmdb utility", comm: "rpmdb", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPackageManagerComm(tt.comm); got != tt.want {
				t.Fatalf("isPackageManagerComm(%q) = %v, want %v", tt.comm, got, tt.want)
			}
		})
	}
}
