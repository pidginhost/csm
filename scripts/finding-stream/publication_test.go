package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDestinationTraversalAliasesRefuseBeforeSalt(t *testing.T) {
	for _, variant := range []string{"symlink dotdot input", "dangling parent salt", "dangling parent outputs", "output ancestor", "case aliases", "Unicode aliases"} {
		t.Run(variant, func(t *testing.T) {
			f := newJoinFixture(t)
			if err := os.Remove(f.salt); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(f.dir, "link")
			switch variant {
			case "symlink dotdot input":
				child := filepath.Join(filepath.Dir(f.findings), "child")
				if err := os.Mkdir(child, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(child, link); err != nil {
					t.Fatal(err)
				}
				// Join would erase the traversal this test needs to exercise.
				f.out = link + "/../" + filepath.Base(f.findings)
			case "dangling parent salt":
				parent := filepath.Join(f.dir, "missing")
				if err := os.Symlink("missing", link); err != nil {
					t.Fatal(err)
				}
				f.salt = filepath.Join(parent, "salt")
				f.out = filepath.Join(link, "salt")
			case "dangling parent outputs":
				if err := os.Symlink("out", link); err != nil {
					t.Fatal(err)
				}
				f.actionsOut = filepath.Join(link, filepath.Base(f.out))
			case "output ancestor":
				f.actionsOut = filepath.Join(f.out, "child")
			case "case aliases":
				f.actionsOut = filepath.Join(filepath.Dir(f.out), strings.ToUpper(filepath.Base(f.out)))
			case "Unicode aliases":
				f.out = filepath.Join(filepath.Dir(f.out), "caf\u00e9.gz")
				f.actionsOut = filepath.Join(filepath.Dir(f.out), "cafe\u0301.gz")
			}
			before := snapshot(t, f.findings, f.actions, f.firewall, f.salt)
			var stdout bytes.Buffer
			err := testRun().execute(f.args(), &stdout)
			if !errors.Is(err, errOutputAlias) || stdout.Len() != 0 {
				t.Errorf("unsafe destinations not refused before publication: %v", err)
			}
			assertUnchanged(t, before)
		})
	}
}

func TestRunRejectsNonJSONWhitespace(t *testing.T) {
	for _, stream := range []string{"findings", "inventory"} {
		t.Run(stream, func(t *testing.T) {
			f := newJoinFixture(t)
			if err := os.Remove(f.salt); err != nil {
				t.Fatal(err)
			}
			args := f.args()
			if stream == "findings" {
				writeInput(t, f.findings, append([]byte("\u00a0"), f.findingRows...))
			} else {
				inventory := filepath.Join(f.dir, "inventory.json")
				writeInput(t, inventory, []byte("\u00a0"+`{"v":1,"streams":[]}`))
				args = f.args("--input-manifest", inventory)
			}
			var stdout bytes.Buffer
			err := testRun().execute(args, &stdout)
			if !errors.Is(err, errSyntax) || stdout.Len() != 0 {
				t.Errorf("non-JSON input reached validation or publication: %v", err)
			}
			if _, err := os.Stat(f.salt); !errors.Is(err, os.ErrNotExist) {
				t.Error("malformed input created a salt")
			}
		})
	}
}

func TestRunStagesBesideResolvedDestination(t *testing.T) {
	f := newJoinFixture(t)
	parent := filepath.Join(f.dir, "resolved")
	child := filepath.Join(parent, "child")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.dir, "link")
	if err := os.Symlink(child, link); err != nil {
		t.Fatal(err)
	}
	f.out = link + "/../findings.gz"
	r := testRun()
	create := r.ops.createTemp
	first := true
	r.ops.createTemp = func(dir, pattern string) (stagedFile, error) {
		if first {
			first = false
			got, err := os.Stat(dir)
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.Stat(parent)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(got, want) {
				t.Error("staging is not on the destination filesystem")
			}
		}
		return create(dir, pattern)
	}
	if err := r.execute(f.args(), io.Discard); err != nil {
		t.Fatal(err)
	}
	if first {
		t.Fatal("no output was staged")
	}
	rows, _ := readGzipRows(t, filepath.Join(parent, "findings.gz"))
	if len(rows) != len(f.findingsRaw) {
		t.Fatal("output did not reach the resolved destination")
	}
}

func TestCleanupFailureNeverReportsSuccess(t *testing.T) {
	for _, phase := range []string{"stage", "staged earlier", "publish backup", "publish temp", "committed backup"} {
		t.Run(phase, func(t *testing.T) {
			f := newJoinFixture(t)
			if err := testRun().execute(f.args(), io.Discard); err != nil {
				t.Fatal(err)
			}
			before := snapshot(t, f.outputs()...)
			f.findingsRaw[0].Message = "changed message"
			f.findingRows = encodeLines(t, anySlice(f.findingsRaw)...)
			f.write(t)
			r := testRun()
			switch phase {
			case "stage":
				injectFailure(r, "write", 2)
			case "staged earlier":
				injectFailure(r, "create", 2)
			case "publish backup", "publish temp":
				injectFailure(r, "rename", 2)
			}
			remove := r.ops.remove
			failed := false
			r.ops.remove = func(path string) error {
				backup := strings.HasPrefix(filepath.Base(path), backupPrefix)
				if backup == (phase == "publish backup" || phase == "committed backup") {
					failed = true
					return errInjected
				}
				return remove(path)
			}
			var stdout bytes.Buffer
			err := r.execute(f.args(), &stdout)
			if !failed {
				t.Fatal("cleanup fault was not exercised")
			}
			want := errCleanup
			if phase == "committed backup" {
				want = errPublishedCleanup
			}
			if !errors.Is(err, want) || stdout.Len() != 0 {
				t.Errorf("cleanup failure was hidden: %v, stdout = %q", err, stdout.String())
			}
			entries, readErr := os.ReadDir(filepath.Dir(f.out))
			if readErr != nil {
				t.Fatal(readErr)
			}
			backups, temps := 0, 0
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), backupPrefix) {
					backups++
				} else if strings.HasPrefix(entry.Name(), ".finding-stream-") {
					temps++
				}
			}
			wantBackups, wantTemps := 0, 0
			switch phase {
			case "stage":
				wantTemps = 2
			case "staged earlier":
				wantTemps = 1
			case "publish backup":
				wantBackups = 1
			case "publish temp":
				wantTemps = 3
			case "committed backup":
				wantBackups = 4
			}
			if backups != wantBackups || temps != wantTemps {
				t.Errorf("leftover files: backups=%d temps=%d, want %d %d", backups, temps, wantBackups, wantTemps)
			}
			if phase == "committed backup" {
				if err != nil && strings.Contains(err.Error(), "unchanged") {
					t.Error("committed output was falsely reported unchanged")
				}
				_, body := readGzipRows(t, f.out)
				if !strings.Contains(body, "changed message") {
					t.Error("commit did not publish the new output")
				}
			} else {
				assertUnchanged(t, before)
			}
		})
	}
}
