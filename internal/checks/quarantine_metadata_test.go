package checks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestQuarantineMetadataReadsLegacyTimestamp(t *testing.T) {
	var meta QuarantineMeta
	if err := json.Unmarshal([]byte(`{"original_path":"/home/alice/site.php","owner_uid":1001,"group_gid":1002,"mode":"-rwxr-x---","size":42,"quarantine_at":"2026-09-04T10:00:00.123456789+03:00","reason":"manual fix"}`), &meta); err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 9, 4, 7, 0, 0, 123456789, time.UTC)
	if !meta.QuarantineAt.Equal(want) || meta.OriginalPath != "/home/alice/site.php" || meta.Owner != 1001 || meta.Group != 1002 || meta.Mode != "-rwxr-x---" || meta.Size != 42 || meta.Reason != "manual fix" {
		t.Fatalf("legacy sidecar lost metadata: %+v", meta)
	}
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"quarantine_at"`) || strings.Contains(string(data), `"original_mtime"`) {
		t.Fatalf("rewritten legacy sidecar contains legacy spelling or fabricated mtime: %s", data)
	}
}

func TestQuarantineWritersPreserveOriginalMetadata(t *testing.T) {
	for _, kind := range []string{"automatic", "inline", "manual", "php-clean", "htaccess-clean", "legacy-htaccess", "crontab"} {
		t.Run(kind, func(t *testing.T) {
			root := mustEvalSymlinks(t, t.TempDir())
			qDir := t.TempDir()
			withQuarantineDirCF(t, qDir)
			withHtaccessBackupRoot(t)
			oldRoots := fixHtaccessAllowedRoots
			fixHtaccessAllowedRoots = []string{root}
			t.Cleanup(func() { fixHtaccessAllowedRoots = oldRoots })
			withCrontabAllowedRoots(t, root)
			name, content := "source.php", "<?php\n@include('/tmp/evil.php');\necho 'safe';\n"
			if kind == "htaccess-clean" || kind == "legacy-htaccess" {
				name, content = ".htaccess", "# keep\nAddHandler cgi-script .alfa\n# end\n"
			}
			if kind == "inline" {
				content = string(makeHighEntropyContent(t, 2048))
			}
			path := filepath.Join(root, name)
			if err := os.WriteFile(path, []byte(content), 0750); err != nil {
				t.Fatal(err)
			}
			if os.Geteuid() == 0 {
				if err := os.Chown(path, 1001, 1002); err != nil {
					t.Fatal(err)
				}
			}
			stamp := time.Date(2024, 2, 3, 4, 5, 6, 123456789, time.UTC)
			if err := os.Chtimes(path, stamp, stamp); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			before := time.Now()
			var reason string
			switch kind {
			case "automatic":
				reason = "detected test evidence"
				cfg := &config.Config{}
				cfg.AutoResponse.Enabled, cfg.AutoResponse.QuarantineFiles = true, true
				got := AutoQuarantineFiles(cfg, []alert.Finding{{Check: "backdoor_binary", Severity: alert.Critical, FilePath: path, Message: reason}})
				if len(got) != 1 {
					t.Fatalf("automatic quarantine actions=%v", got)
				}
			case "manual":
				reason = "Fixed via CSM Web UI"
				if result := quarantineResolvedTarget(path, info); !result.Success {
					t.Fatal(result)
				}
			case "inline":
				reason = "Inline quarantine: high-confidence realtime signature match"
				finding := alert.Finding{Check: "yara_match", Details: "Category: dropper\nRule: webshell_generic\n"}
				if _, ok := InlineQuarantine(finding, path, []byte(content)); !ok {
					t.Fatal("inline quarantine failed")
				}
			case "php-clean":
				reason = "Pre-clean backup (surgical cleaning)"
				if result := CleanInfectedFile(path); !result.Cleaned {
					t.Fatal(result)
				}
				qDir = filepath.Join(qDir, "pre_clean")
			case "htaccess-clean":
				if result := CleanHtaccessFile(path); !result.Success {
					t.Fatal(result)
				}
				reason = fmt.Sprintf("htaccess clean: 1 ranges removed (%d -> %d bytes)", len(content), len("# keep\n# end\n"))
				qDir = htaccessBackupDirRoot
			case "legacy-htaccess":
				reason = "Pre-clean .htaccess backup"
				if result := fixHtaccess(path, "test"); !result.Success {
					t.Fatal(result)
				}
				qDir = htaccessBackupDirRoot
			case "crontab":
				reason = "suspicious_crontab remediation"
				if result := fixSuspiciousCrontab(path); !result.Success {
					t.Fatal(result)
				}
			}
			after := time.Now()
			entries, err := os.ReadDir(qDir)
			if err != nil || len(entries) != 2 {
				t.Fatalf("expected one sidecar and content, got=%v error=%v", entries, err)
			}
			for _, entry := range entries {
				data, readErr := os.ReadFile(filepath.Join(qDir, entry.Name()))
				if readErr != nil {
					t.Fatal(readErr)
				}
				if !strings.HasSuffix(entry.Name(), ".meta") {
					if string(data) != content {
						t.Fatalf("backup content=%q, want=%q", data, content)
					}
					continue
				}
				var meta QuarantineMeta
				if err := json.Unmarshal(data, &meta); err != nil {
					t.Fatal(err)
				}
				st := info.Sys().(*syscall.Stat_t)
				if meta.OriginalPath != path || meta.Owner != int(st.Uid) || meta.Group != int(st.Gid) || meta.Mode != info.Mode().String() || meta.Size != info.Size() || !meta.OriginalModTime.Equal(info.ModTime()) || meta.QuarantineAt.Before(before) || meta.QuarantineAt.After(after) || meta.Reason != reason {
					t.Fatalf("incorrect %s sidecar: %s; expected original stat=%+v", kind, data, info)
				}
				if strings.Contains(string(data), `"quarantine_at"`) {
					t.Fatalf("writer emitted legacy timestamp: %s", data)
				}
			}
		})
	}
}

func TestQuarantineMetadataTimestampDecoding(t *testing.T) {
	stamp := time.Date(2026, 9, 5, 1, 2, 3, 123456789, time.UTC)
	for _, tc := range []struct {
		name, data string
		want       time.Time
		wantError  bool
	}{
		{"canonical wins", `{"quarantined_at":"2026-09-05T01:02:03.123456789Z","quarantine_at":"2020-01-01T00:00:00Z"}`, stamp, false},
		{"canonical null uses legacy", `{"quarantined_at":null,"quarantine_at":"2026-09-05T01:02:03.123456789Z"}`, stamp, false},
		{"missing", `{}`, time.Time{}, false},
		{"null", `{"quarantined_at":null,"quarantine_at":null,"original_mtime":null}`, time.Time{}, false},
		{"invalid canonical", `{"quarantined_at":"invalid"}`, time.Time{}, true},
		{"invalid legacy", `{"quarantine_at":42}`, time.Time{}, true},
		{"invalid original", `{"original_mtime":"invalid"}`, time.Time{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previous := QuarantineMeta{QuarantineAt: stamp, OriginalModTime: stamp, OriginalPath: "/previous"}
			meta := previous
			err := json.Unmarshal([]byte(tc.data), &meta)
			if (err != nil) != tc.wantError {
				t.Fatalf("decode error=%v, wantError=%v", err, tc.wantError)
			}
			if tc.wantError {
				if meta != previous {
					t.Fatalf("failed decode changed destination: %+v", meta)
				}
				return
			}
			if !meta.QuarantineAt.Equal(tc.want) || !meta.OriginalModTime.IsZero() || meta.OriginalPath != "" {
				t.Fatalf("decoded metadata=%+v, want date=%v and other fields reset", meta, tc.want)
			}
		})
	}
}
