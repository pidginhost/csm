package antispam

import (
	"io/fs"
	"net/netip"
	"testing"
)

func TestControllerExposureAddressForms(t *testing.T) {
	for _, tt := range []struct {
		name, trust, host, reason string
	}{
		{"mapped host trust", "::ffff:203.0.113.10", "203.0.113.10/32", exposureTrusted},
		{"mapped host network", "::ffff:203.0.113.129/120", "203.0.113.10/24", exposureTrusted},
		{"mapped interface", "203.0.113.10", "::ffff:203.0.113.10/128", exposureTrusted},
		{"mapped interface network", "203.0.113.129/24", "::ffff:203.0.113.10/120", exposureTrusted},
		{"IPv4 interface address", "203.0.113.10", "203.0.113.10/24", exposureTrusted},
		{"IPv4 subnet peer", "203.0.113.11", "203.0.113.10/24", ""},
		{"IPv6 subnet peer", "2001:db8::11", "2001:db8::10/64", ""},
		{"mapped subnet peer", "::ffff:203.0.113.11", "::ffff:203.0.113.10/120", ""},
		{"masked trust", "203.0.113.129/24", "203.0.113.10/32", exposureTrusted},
		{"neighboring trust", "203.0.113.129/25", "203.0.113.10/32", ""},
		{"wide mapped trust", "::ffff:203.0.113.10/95", "2001:db8::10/128", exposureTrusted},
		{"IPv6 wildcard", "2001:db8::10/0", "203.0.113.10/32", exposureTrusted},
		{"IPv4 wildcard", "203.0.113.10/0", "2001:db8::10/128", exposureTrusted},
		{"zoned trust", "2001:db8::10%eth0", "2001:db8::10/128", exposureUnresolved},
		{"zoned loopback", "::1%lo", "203.0.113.10/32", exposureUnresolved},
		{"zoned prefix", "2001:db8::10%eth0/128", "2001:db8::10/128", exposureUnresolved},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := hostFacts()
			f.Addrs = []netip.Prefix{netip.MustParsePrefix(tt.host)}
			got := ControllerExposure(tcpController([]string{tt.trust}, true, true), f)
			if tt.reason == "" {
				if len(got) != 0 {
					t.Fatalf("remote trust: problems = %+v, want none", got)
				}
			} else {
				onlyReason(t, got, "localhost:11334", tt.reason)
			}
		})
	}
}

func TestControllerExposureUnixPathAccess(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*SocketFacts, *ControllerHostFacts)
		reason string
	}{
		{"missing parents", func(s *SocketFacts, _ *ControllerHostFacts) {
			s.Parents = nil
		}, exposureSocketUnknown},
		{"not a socket", func(s *SocketFacts, _ *ControllerHostFacts) {
			s.Socket.Mode = 0o600
		}, exposureSocketUnknown},
		{"unresolved parent symlink", func(s *SocketFacts, _ *ControllerHostFacts) {
			s.Parents[1].Mode = fs.ModeSymlink | 0o755
		}, exposureSocketUnknown},
		{"trusted writable group", func(s *SocketFacts, f *ControllerHostFacts) {
			s.Parents[2].Mode = fs.ModeDir | 0o775
			f.GroupMembers[990] = []string{"root", "_rspamd"}
		}, ""},
		{"tenant writable group", func(s *SocketFacts, f *ControllerHostFacts) {
			s.Parents[2].Mode = fs.ModeDir | 0o775
			// Membership facts include primary GIDs, not just /etc/group names.
			f.GroupMembers[990] = []string{"_rspamd", "tenant1"}
		}, exposureSocketParent},
		{"unknown writable group", func(s *SocketFacts, _ *ControllerHostFacts) {
			s.Parents[2].Mode = fs.ModeDir | 0o775
		}, exposureSocketParent},
		{"group write without search", func(s *SocketFacts, f *ControllerHostFacts) {
			s.Parents[2].Mode = fs.ModeDir | 0o765
			f.GroupMembers[990] = []string{"tenant1"}
		}, ""},
		{"other write without search", func(s *SocketFacts, f *ControllerHostFacts) {
			s.Parents[2].Mode = fs.ModeDir | 0o756
			f.GroupMembers[990] = []string{"root", "_rspamd"}
		}, ""},
		{"private parent hides world socket", func(s *SocketFacts, _ *ControllerHostFacts) {
			s.Socket.Mode = fs.ModeSocket | 0o666
			s.Parents[2].Mode = fs.ModeDir | 0o700
		}, ""},
		{"private ancestor hides foreign owner", func(s *SocketFacts, _ *ControllerHostFacts) {
			s.Parents[1].Mode = fs.ModeDir | 0o700
			s.Parents[2].UID = 1001
			s.Socket.UID = 1001
		}, ""},
		{"trusted search group hides world socket", func(s *SocketFacts, f *ControllerHostFacts) {
			s.Socket.Mode = fs.ModeSocket | 0o666
			s.Parents[2].Mode = fs.ModeDir | 0o750
			f.GroupMembers[990] = []string{"root", "_rspamd"}
		}, ""},
		{"unknown search group exposes world socket", func(s *SocketFacts, _ *ControllerHostFacts) {
			s.Socket.Mode = fs.ModeSocket | 0o666
			s.Parents[2].Mode = fs.ModeDir | 0o750
		}, exposureSocket},
		{"writable ancestor defeats private parent", func(s *SocketFacts, _ *ControllerHostFacts) {
			s.Parents[1].Mode = fs.ModeDir | 0o777
			s.Parents[2].Mode = fs.ModeDir | 0o700
		}, exposureSocketParent},
		{"sticky parent protects socket", func(s *SocketFacts, _ *ControllerHostFacts) {
			s.Parents[2].Mode = fs.ModeDir | fs.ModeSticky | 0o777
		}, ""},
		{"sticky ancestor protects private directory", func(s *SocketFacts, _ *ControllerHostFacts) {
			s.Parents[1].Mode = fs.ModeDir | fs.ModeSticky | 0o777
			s.Parents[2].Mode = fs.ModeDir | 0o700
		}, ""},
		{"sticky parent does not protect foreign directory", func(s *SocketFacts, _ *ControllerHostFacts) {
			s.Parents[1].Mode = fs.ModeDir | fs.ModeSticky | 0o777
			s.Parents[2].UID = 1001
		}, exposureSocketParent},
		{"sticky parent does not restrict socket connections", func(s *SocketFacts, _ *ControllerHostFacts) {
			s.Parents[2].Mode = fs.ModeDir | fs.ModeSticky | 0o777
			s.Socket.Mode = fs.ModeSocket | 0o666
		}, exposureSocket},
		{"parent ACL cannot prove privacy", func(s *SocketFacts, _ *ControllerHostFacts) {
			s.Parents[2].Mode = fs.ModeDir | 0o700
			s.Parents[2].ExtACL = true
		}, exposureSocketParent},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := hostFacts()
			s := unixSocket(990, 990, 0o600)
			tt.change(&s, &f)
			f.Sockets[unixPath] = s
			got := ControllerExposure(unixController(), f)
			if tt.reason == "" {
				if len(got) != 0 {
					t.Fatalf("protected socket: problems = %+v, want none", got)
				}
			} else {
				onlyReason(t, got, unixPath+" mode=0600", tt.reason)
			}
		})
	}
}

func TestControllerExposureSymlinkedSocketParents(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mode   fs.FileMode
		reason string
	}{
		{"protected symlink directory", fs.ModeDir | 0o755, ""},
		{"replaceable symlink", fs.ModeDir | 0o777, exposureSocketParent},
		// SocketFacts does not carry the symlink owner's UID. A sticky bit
		// cannot prove that a tenant cannot replace that symlink.
		{"unknown symlink owner under sticky directory", fs.ModeDir | fs.ModeSticky | 0o777, exposureSocketUnknown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := hostFacts()
			s := unixSocket(990, 990, 0o600)
			s.Parents = []PathFacts{s.Parents[0], {Path: "/var", UID: 0, Mode: tt.mode}, s.Parents[1], s.Parents[2]}
			const linkPath = "/var/run/rspamd/csm-controller.sock"
			f.Sockets[linkPath] = s
			c := ControllerConfig{Present: true, Listeners: []ControllerListener{{Raw: linkPath, Unix: true, Path: linkPath}}}
			got := ControllerExposure(c, f)
			if tt.reason == "" {
				if len(got) != 0 {
					t.Fatalf("protected symlink: problems = %+v, want none", got)
				}
			} else {
				onlyReason(t, got, linkPath, tt.reason)
			}
		})
	}
}
