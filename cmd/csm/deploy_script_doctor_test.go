package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func doctorDeployDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := deployScriptSearchPaths
	t.Cleanup(func() { deployScriptSearchPaths = old })
	deployScriptSearchPaths = []string{dir}
	return dir
}

func writeDoctorDeployScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func shippedDeployScripts(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob("../../scripts/deploy*.sh")
	if err != nil || len(paths) == 0 {
		t.Fatalf("locating shipped deploy scripts: %v, %v", paths, err)
	}
	return paths
}

func TestDoctorNamesCurrentDeployScripts(t *testing.T) {
	dir := doctorDeployDir(t)
	var want []string
	for _, source := range shippedDeployScripts(t) {
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		// A filename must stay on one line in the human report.
		path := writeDoctorDeployScript(t, dir, "local\n"+filepath.Base(source), string(data))
		want = append(want, strconv.Quote(path))
		if err := os.Symlink(path, filepath.Join(dir, "z-"+filepath.Base(path))); err != nil {
			t.Fatal(err)
		}
	}
	checks := deployScriptDoctorChecks()
	if len(checks) != 1 || checks[0].Status != "ok" || checks[0].Message != "checked "+strings.Join(want, ", ") || checks[0].Fix != "" {
		t.Fatalf("expected one OK naming each shipped script once, got %+v", checks)
	}
}

const csmDeployHeader = "#!/bin/bash\n# Continuous Security Monitor - Deploy from GitHub Releases\n"

func TestDoctorDeployScriptClassification(t *testing.T) {
	for _, tc := range []struct{ name, body, status string }{
		{"openssl skip", csmDeployHeader + `verify_signature() { echo "skipping signature check"; return 0; }`, "fail"},
		{"missing key skip", csmDeployHeader + `verify_signature() { echo "skipping signature verification"; return 0; }`, "fail"},
		{"comment", csmDeployHeader + "# TODO: call verify_signature", "warn"},
		{"no verifier", csmDeployHeader + "echo upgrading", "warn"},
		{"unrelated", "#!/bin/bash\necho hello", ""},
		{"other product with legacy verifier", "#!/bin/bash\nverify_signature() { echo 'skipping signature check'; }", ""},
		{"other product with verifier", "#!/bin/bash\nverify_signature() { :; }", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeDoctorDeployScript(t, doctorDeployDir(t), "custom-deploy.sh", tc.body)
			checks := deployScriptDoctorChecks()
			if tc.status == "" {
				if len(checks) != 0 {
					t.Fatalf("unexpected checks: %+v", checks)
				}
				return
			}
			if len(checks) != 1 || checks[0].Status != tc.status || !strings.Contains(checks[0].Message, path) || checks[0].Fix == "" {
				t.Fatalf("expected %s naming the script with a remedy, got %+v", tc.status, checks)
			}
		})
	}
}

func TestDoctorDeployIncompleteInspection(t *testing.T) {
	dir := doctorDeployDir(t)
	data, err := os.ReadFile("../../scripts/deploy.sh")
	if err != nil {
		t.Fatal(err)
	}
	writeDoctorDeployScript(t, dir, "deploy.sh", string(data))
	tooLarge := writeDoctorDeployScript(t, dir, "deploy-large.sh", strings.Repeat(" ", maxDeployScriptBytes+1))
	broken := filepath.Join(dir, "deploy-broken.sh")
	if err := os.Symlink("gone", broken); err != nil {
		t.Fatal(err)
	}
	notDir := writeDoctorDeployScript(t, dir, "not-a-directory", "")
	deployScriptSearchPaths = append(deployScriptSearchPaths, notDir)

	assertIncomplete := func(want string) {
		t.Helper()
		checks := deployScriptDoctorChecks()
		if collapseDoctor(checks) != want {
			t.Fatalf("expected overall %s, got %+v", want, checks)
		}
		var message string
		for _, c := range checks {
			if c.Status == "ok" || c.Fix == "" {
				t.Fatalf("unexpected check: %+v", c)
			}
			message += c.Message
		}
		for _, path := range []string{tooLarge, broken, notDir} {
			if !strings.Contains(message, path) {
				t.Errorf("missing %s in %+v", path, checks)
			}
		}
		if want == "fail" && !strings.Contains(message, "deploy-old.sh") {
			t.Errorf("missing stale script in %+v", checks)
		}
	}
	assertIncomplete("warn")
	writeDoctorDeployScript(t, dir, "deploy-old.sh", csmDeployHeader+`verify_signature() { echo "skipping signature check"; }`)
	assertIncomplete("fail")
}

func TestDoctorDeployFIFO(t *testing.T) {
	dir := doctorDeployDir(t)
	fifo := filepath.Join(dir, "deploy-pipe.sh")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan []DoctorCheck, 1)
	go func() { done <- deployScriptDoctorChecks() }()
	select {
	case checks := <-done:
		if len(checks) != 1 || checks[0].Status != "warn" || !strings.Contains(checks[0].Message, fifo) {
			t.Fatalf("expected warning for unreadable script, got %+v", checks)
		}
	case <-time.After(2 * time.Second):
		writer, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		<-done
		_ = writer.Close()
		t.Fatal("doctor blocked opening a FIFO")
	}
}

// A directory that does not exist, or holds nothing deploy-shaped, is normal.
func TestDoctorDeployScriptCheckStaysQuietWithoutScripts(t *testing.T) {
	old := deployScriptSearchPaths
	t.Cleanup(func() { deployScriptSearchPaths = old })
	deployScriptSearchPaths = []string{filepath.Join(t.TempDir(), "absent"), t.TempDir()}
	if checks := deployScriptDoctorChecks(); len(checks) != 0 {
		t.Fatalf("unexpected checks: %+v", checks)
	}
}
