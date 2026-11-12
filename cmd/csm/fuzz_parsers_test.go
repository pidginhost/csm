package main

import (
	"strings"
	"testing"
)

func FuzzCSMWorkerCgroup(f *testing.F) {
	for _, seed := range []string{
		"",
		`/system.slice/system-csm\x2dyara\x2dworker.slice/csm-yara-worker-1.service`,
		`/system.slice/system-csm\x2dyara\x2dcompile\x2dworker.slice/csm-yara-compile-worker-2.service`,
		`/system.slice/system-csm\x2dparse\x2dworker\x2dmail0.slice/csm-parse-worker-mail0-3.service`,
		`/system.slice/system-csm\x2dparse\x2dworker\x2dcli\x2d123.slice/csm-parse-worker-cli-123-4.service`,
		`/system.slice/system-csm\x2dphptaint\x2dworker.slice/csm-phptaint-worker-5.service`,
		`/system.slice/system-123.slice/123-1.service`,
		"../csm-yara-worker-1.service",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, path string) {
		if isCSMWorkerCgroup(path) {
			if !strings.HasPrefix(path, `/system.slice/system-csm\x2d`) || strings.Count(path, "/") != 3 {
				t.Fatalf("accepted a path outside a direct CSM unit: %q", path)
			}
			if isCSMWorkerCgroup(strings.Replace(path, "/system.slice/", "/user.slice/", 1)) {
				t.Fatalf("accepted a user-controlled unit: %q", path)
			}
		}
		// A tenant may choose any descendant name inside a delegated service.
		if isCSMWorkerCgroup(`/system.slice/system-csm\x2dhosting.slice/tenant.service/` + path) {
			t.Fatalf("accepted a delegated descendant: %q", path)
		}
	})
}

func FuzzStalwartSocketAddress(f *testing.F) {
	for _, seed := range []string{"0100007F:1F90", "00000000000000000000000001000000:01BB", "", "bad:port"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		addr, err := procSocketAddress(raw)
		if err == nil && !addr.IsValid() {
			t.Fatal("successful parse returned an invalid socket address")
		}
	})
}
