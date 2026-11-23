package platform

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// A nondumpable process can deny exe access even to a privileged inspector
// without CAP_SYS_PTRACE. Its comm is still entirely chosen by its owner.
// A process whose executable cannot be read is identified only by the name
// it gives itself, which its own code can change. It never locates server
// configuration, but whatever it runs as counts as a possible runtime user,
// and an unidentifiable root process stops the inspection.
func TestPHPRuntimeUsersUntrustedExecutableError(t *testing.T) {
	const unknown = "a running process whose executable cannot be verified"
	for _, name := range []string{"lshttpd", "litespeed", "openlitespeed", "unrelated", "php-fpm8.2", "php-cgi", "lsphp", "fcgiwrap"} {
		for _, credentials := range []struct {
			name, uids string
			want       map[uint32]string
			wantErr    bool
		}{
			{"tenant", "1001\t1001\t1001\t1001", map[uint32]string{1001: unknown}, false},
			{"web server user", "33\t33\t33\t33", map[uint32]string{33: unknown}, false},
			{"different filesystem user", "1001\t1001\t1001\t33", map[uint32]string{1001: unknown, 33: unknown}, false},
			{"setuid", "1001\t0\t0\t0", map[uint32]string{0: unknown}, false},
			{"root", "0\t0\t0\t0", nil, true},
		} {
			t.Run(name+"/"+credentials.name, func(t *testing.T) {
				root := t.TempDir()
				writeRootFile(t, root, "etc/passwd", testPasswd)
				// readlink on a regular file supplies a non-ENOENT failure without
				// requiring root or changing the test runner's capabilities.
				writeRootFile(t, root, "proc/300/exe", "")
				writeRootFile(t, root, "proc/300/comm", name+"\n")
				writeRootFile(t, root, "proc/300/cmdline", "php-fpm: master process (/etc/php-fpm.conf)\x00")
				writeRootFile(t, root, "proc/300/status", "Uid:\t"+credentials.uids+"\n")
				got, err := phpRuntimeUsers(root)
				if credentials.wantErr {
					if err == nil {
						t.Fatal("uninspectable root process accepted as isolated")
					}
				} else if err != nil || !maps.Equal(got, credentials.want) {
					t.Fatalf("users = %v, error = %v; want %v", got, err, credentials.want)
				}
			})
		}
	}
}

func TestPHPRuntimeUsersUntrustedSpecialConfig(t *testing.T) {
	for _, name := range []string{"httpd_config.xml", "httpd_config.conf"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeRootFile(t, root, "etc/passwd", testPasswd)
			fakeProc(t, root, 300, "/home/site1/bin/lshttpd", 1001)
			conf := filepath.Join(root, "home/site1/conf")
			if err := os.MkdirAll(conf, 0755); err != nil {
				t.Fatal(err)
			}
			// /dev/null would parse as an invalid configuration if it were read.
			// It safely proves that even a special-file symlink is never followed.
			if err := os.Symlink("/dev/null", filepath.Join(conf, name)); err != nil {
				t.Fatal(err)
			}
			got, err := phpRuntimeUsers(root)
			if err != nil || !maps.Equal(got, map[uint32]string{1001: "a running process whose executable cannot be verified"}) {
				t.Fatalf("users = %v, error = %v; tenant configuration inspected", got, err)
			}
		})
	}
}

// Replacing a PID directory must not replace the process an inspection has
// opened. Otherwise a tenant's exe can be paired with a new root process UID.
func TestPHPProcessUserPinsIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, oldExe, newExe string
		oldUID, newUID       int
		want                 map[uint32]string
	}{
		{"tenant replaced by root", "/home/site1/bin/lshttpd", "/usr/bin/sleep", 1001, 0, map[uint32]string{1001: "a running process whose executable cannot be verified"}},
		{"worker replaced by root", "/usr/bin/php-cgi", "/usr/bin/sleep", 1001, 0, map[uint32]string{1001: "a running php-cgi process"}},
		{"root server replaced by tenant", "/opt/server/bin/lshttpd", "/home/site1/bin/lshttpd", 0, 1001, map[uint32]string{33: "LiteSpeed's PHP handler"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			fakeProc(t, root, 300, tc.oldExe, tc.oldUID)
			writeRootFile(t, root, "opt/server/conf/httpd_config.conf", "user www-data\n")
			dir := filepath.Join(root, "proc/300")
			proc, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = proc.Close() }()
			snapshot := replacingProcessExe{Root: proc, replace: func() {
				if renameErr := os.Rename(dir, dir+"-exited"); renameErr != nil {
					t.Fatal(renameErr)
				}
				fakeProc(t, root, 300, tc.newExe, tc.newUID)
			}}
			got := map[uint32]string{}
			err = phpProcessUser(root, snapshot, func(uid uint32, source string) { got[uid] = source }, func(name, source string) error {
				if name != "www-data" {
					t.Fatalf("unexpected configuration user %q", name)
				}
				got[33] = source
				return nil
			}, fixturePHPExecutableTrusted)
			if err != nil || !maps.Equal(got, tc.want) {
				t.Fatalf("users = %v, error = %v; want original process users %v", got, err, tc.want)
			}
		})
	}
}

type replacingProcessExe struct {
	*os.Root
	replace func()
}

func (p replacingProcessExe) Readlink(name string) (string, error) {
	exe, err := p.Root.Readlink(name)
	p.replace()
	return exe, err
}

type failingProcessFile struct {
	*os.Root
	file string
	err  error
}

func (p failingProcessFile) ReadFile(name string) ([]byte, error) {
	if name == p.file {
		return nil, &os.PathError{Op: "read", Path: name, Err: p.err}
	}
	return p.Root.ReadFile(name)
}

// Procfs returns ESRCH when a process exits after open but before read.
// Permission errors on credentials must still fail closed.
func TestPHPProcessUserExitDuringRead(t *testing.T) {
	for _, name := range []string{"lshttpd", "php-cgi"} {
		for _, file := range []string{"stat", "status"} {
			for _, readErr := range []error{syscall.ESRCH, os.ErrPermission} {
				t.Run(name+"/"+file+"/"+readErr.Error(), func(t *testing.T) {
					root := t.TempDir()
					if file == "status" {
						fakeProc(t, root, 300, "/opt/server/bin/"+name, 0)
					} else {
						writeRootFile(t, root, "proc/300/comm", name)
						writeRootFile(t, root, "proc/300/status", "Uid:\t0\t0\t0\t0\n")
					}
					proc, err := os.OpenRoot(filepath.Join(root, "proc/300"))
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = proc.Close() }()
					err = phpProcessUser(root, failingProcessFile{proc, file, readErr}, func(uint32, string) { t.Fatal("added an exited process") }, func(string, string) error { t.Fatal("read configuration for an exited process"); return nil }, fixturePHPExecutableTrusted)
					if readErr == syscall.ESRCH {
						if err != nil {
							t.Fatalf("process exit stopped inspection: %v", err)
						}
					} else if !errors.Is(err, readErr) {
						t.Fatalf("lost credential error: %v", err)
					}
				})
			}
		}
	}
}

// A setuid executable retains the caller's real UID. A title supplied by
// that caller cannot establish a root-owned FPM supervisor.
func TestPHPProcessUserUntrustedSupervisorTitle(t *testing.T) {
	root := t.TempDir()
	writeRootFile(t, root, "etc/passwd", testPasswd)
	fakeProc(t, root, 300, "/home/site1/bin/php-fpm", 1001)
	writeRootFile(t, root, "proc/300/status", "Uid:\t1001\t0\t0\t0\n")
	writeRootFile(t, root, "proc/300/cmdline", "php-fpm: master process (/etc/php-fpm.conf)\x00")
	got, err := phpRuntimeUsers(root)
	if err != nil || !maps.Equal(got, map[uint32]string{0: "a running php-fpm process"}) {
		t.Fatalf("users = %v, error = %v; caller-controlled title hid UID 0", got, err)
	}
}

func TestPHPProcessUserMissingRootWorkerExecutable(t *testing.T) {
	root := t.TempDir()
	writeRootFile(t, root, "etc/passwd", testPasswd)
	writeRootFile(t, root, "proc/300/comm", "php-fpm\n")
	writeRootFile(t, root, "proc/300/stat", "300 (php-fpm) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1\n")
	writeRootFile(t, root, "proc/300/status", "Uid:\t0\t0\t0\t0\n")
	writeRootFile(t, root, "proc/300/cmdline", "php-fpm: master process (/etc/php-fpm.conf)\x00")
	if _, err := phpRuntimeUsers(root); err == nil {
		t.Fatal("unidentifiable root worker did not stop inspection")
	}
}

// Readability does not make a name trustworthy: a copied executable or a
// root-owned hard link in a writable directory can be named by its caller.
func TestPHPRuntimeUsersRenamedExecutable(t *testing.T) {
	for _, name := range []string{"unrelated", "lshttpd", "php-fpm"} {
		for _, uid := range []int{33, 1001} {
			t.Run(name+"/"+strconv.Itoa(uid), func(t *testing.T) {
				root := t.TempDir()
				writeRootFile(t, root, "etc/passwd", testPasswd)
				binary := filepath.Join(root, "home/site1/bin", name)
				writeRootFile(t, root, "home/site1/bin/"+name, "fixture")
				fakeProc(t, root, 300, binary, uid)
				got, err := phpRuntimeUsers(root)
				if err != nil || len(got) != 1 || got[uint32(uid)] == "" {
					t.Fatalf("users = %v, error = %v; renamed executable hid UID %d", got, err, uid)
				}
			})
		}
	}
}

func TestPHPProcessUserMissingExecutableLiveness(t *testing.T) {
	for _, tc := range []struct {
		name, state, flags, threads string
		uid                         int
		wantUID, wantErr            bool
	}{
		{"live renamed worker", "S", "0", "1", 33, true, false},
		{"live root worker", "S", "0", "1", 0, false, true},
		{"zombie with surviving threads", "Z", "0", "2", 33, false, true},
		{"root zombie with surviving threads", "Z", "0", "2", 0, false, true},
		{"zombie", "Z", "0", "1", 33, false, false},
		{"root zombie", "Z", "0", "1", 0, false, false},
		{"kernel thread", "S", "2097152", "1", 0, false, false},
		{"invalid stat", "S", "bad", "1", 33, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeRootFile(t, root, "etc/passwd", testPasswd)
			writeRootFile(t, root, "proc/300/comm", "unrelated\n")
			u := strconv.Itoa(tc.uid)
			writeRootFile(t, root, "proc/300/status", "Uid:\t"+u+"\t"+u+"\t"+u+"\t"+u+"\n")
			writeRootFile(t, root, "proc/300/stat", "300 (unrelated) "+tc.state+" 1 1 1 0 -1 "+tc.flags+" 0 0 0 0 0 0 0 0 20 0 "+tc.threads+" 0 1\n")
			got, err := phpRuntimeUsers(root)
			want := map[uint32]string{}
			if tc.wantUID {
				want[uint32(tc.uid)] = "a running process whose executable cannot be verified"
			}
			if (err != nil) != tc.wantErr || (!tc.wantErr && !maps.Equal(got, want)) {
				t.Fatalf("users = %v, error = %v; want UID=%v, error=%v", got, err, tc.wantUID, tc.wantErr)
			}
		})
	}
}

func TestPHPProcessUserCopiedRootSupervisor(t *testing.T) {
	root := t.TempDir()
	writeRootFile(t, root, "etc/passwd", testPasswd)
	fakeProc(t, root, 300, "/home/site1/bin/php-fpm", 0)
	writeRootFile(t, root, "proc/300/cmdline", "php-fpm: master process (/etc/php-fpm.conf)\x00")
	got, err := phpRuntimeUsers(root)
	if err != nil || !maps.Equal(got, map[uint32]string{0: "a running php-fpm process"}) {
		t.Fatalf("users = %v, error = %v; copied executable and title hid root", got, err)
	}
}
