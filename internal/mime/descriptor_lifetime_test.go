package mime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscardedPartsCloseDescriptors(t *testing.T) {
	for _, kind := range []string{"multipart", "zip", "tgz"} {
		for _, failure := range []string{"size", "budget", "write"} {
			t.Run(kind+"/"+failure, func(t *testing.T) {
				payload := []byte(strings.Repeat("x", 4096))
				name, prefix := "part.bin", "csm-emailav-*"
				switch kind {
				case "zip":
					payload = orderedZip(t, archiveEntry{"leaf.txt", payload})
					name, prefix = "part.zip", "csm-emailav-zip-*"
				case "tgz":
					payload = orderedTarGz(t, archiveEntry{"leaf.txt", payload})
					name, prefix = "part.tgz", "csm-emailav-tgz-*"
				}
				hPath, dPath := multipartSpool(t, attachment{name, payload})
				h, d := openPair(t, hPath, dPath)
				limits := DefaultLimits()
				switch failure {
				case "size":
					limits.MaxAttachmentSize = 512
				case "budget":
					limits.MaxExtractionSize = 2048
				}
				dir := t.TempDir()
				var files []*os.File
				limits.PartSink = func(p string) (*os.File, error) {
					var f *os.File
					var err error
					if failure == "write" && p == prefix {
						f, err = os.OpenFile(filepath.Join(dir, "readonly"), os.O_CREATE|os.O_RDONLY, 0600)
					} else {
						f, err = os.CreateTemp(dir, p)
					}
					if err == nil {
						files = append(files, f)
					}
					return f, err
				}
				result, err := ParseSpoolFiles(h, d, limits)
				if err != nil {
					t.Fatal(err)
				}
				defer result.Close()
				kept := 0
				if kind != "multipart" {
					kept = 1
				}
				if !result.Partial || len(files) != kept+1 || len(result.Parts) != kept {
					t.Fatalf("created=%d, kept=%d, partial=%v (%s)", len(files), len(result.Parts), result.Partial, result.PartialReason)
				}
				for i, f := range files {
					_, err := f.Stat()
					if i < kept && err != nil {
						t.Errorf("retained descriptor was closed: %v", err)
					} else if i >= kept && !errors.Is(err, os.ErrClosed) {
						_ = f.Close()
						t.Errorf("discarded descriptor remains open: %v", err)
					}
				}
				result.Close()
				for _, f := range files {
					if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
						t.Errorf("descriptor remains open after Close: %v", err)
					}
				}
			})
		}
	}
}

func TestArchivePartsShareDescriptorCap(t *testing.T) {
	entries := []archiveEntry{{"first.txt", []byte("first")}, {"second.txt", []byte("second")}}
	for name, data := range map[string][]byte{
		"parts.zip": orderedZip(t, entries...),
		"parts.tgz": orderedTarGz(t, entries...),
	} {
		for cap := 1; cap <= 3; cap++ {
			t.Run(fmt.Sprintf("%s/%d", name, cap), func(t *testing.T) {
				hPath, dPath := multipartSpool(t, attachment{name, data})
				h, d := openPair(t, hPath, dPath)
				limits := DefaultLimits()
				limits.MaxParts = cap
				dir := t.TempDir()
				calls := 0
				limits.PartSink = func(prefix string) (*os.File, error) {
					calls++
					return os.CreateTemp(dir, prefix)
				}
				result, err := ParseSpoolFiles(h, d, limits)
				if err != nil {
					t.Fatal(err)
				}
				defer result.Close()
				if calls != cap || len(result.Parts) != cap || result.Partial != (cap < 3) {
					t.Fatalf("created=%d, parts=%d, partial=%v (%s)", calls, len(result.Parts), result.Partial, result.PartialReason)
				}
				if cap < 3 && result.PartialReason != fmt.Sprintf("message has more than %d attachments", cap) {
					t.Fatalf("wrong limit reason: %q", result.PartialReason)
				}
				for i, part := range result.Parts[1:] {
					if part.Filename != entries[i].name || string(partBytes(t, part)) != string(entries[i].data) {
						t.Fatalf("member %d changed: %+v", i, part)
					}
				}
			})
		}
	}
}

func TestPartSinkFailureClosesReturnedFile(t *testing.T) {
	for _, kind := range []string{"single", "multipart", "zip", "tgz"} {
		t.Run(kind, func(t *testing.T) {
			var hPath, dPath, failPrefix string
			switch kind {
			case "single":
				hPath, dPath = buildEximSpool(t, "application/octet-stream", "payload")
				failPrefix = "csm-emailav-single-*"
			case "multipart":
				hPath, dPath = multipartSpool(t, attachment{"part.bin", []byte("payload")})
				failPrefix = "csm-emailav-*"
			case "zip":
				hPath, dPath = multipartSpool(t, attachment{"part.zip", orderedZip(t, archiveEntry{"leaf.txt", []byte("payload")})})
				failPrefix = "csm-emailav-zip-*"
			case "tgz":
				hPath, dPath = multipartSpool(t, attachment{"part.tgz", orderedTarGz(t, archiveEntry{"leaf.txt", []byte("payload")})})
				failPrefix = "csm-emailav-tgz-*"
			}
			h, d := openPair(t, hPath, dPath)
			dir := t.TempDir()
			var failed *os.File
			limits := DefaultLimits()
			limits.PartSink = func(prefix string) (*os.File, error) {
				f, err := os.CreateTemp(dir, prefix)
				if err != nil {
					return nil, err
				}
				if prefix == failPrefix {
					failed = f
					return f, errors.New("sink setup failed")
				}
				return f, nil
			}
			result, err := ParseSpoolFiles(h, d, limits)
			if err != nil {
				t.Fatal(err)
			}
			defer result.Close()
			if failed == nil || !result.Partial || !strings.Contains(result.PartialReason, "could not stage") {
				t.Fatalf("failed sink was not reported: %+v", result)
			}
			if _, err := failed.Stat(); !errors.Is(err, os.ErrClosed) {
				_ = failed.Close()
				t.Fatalf("file returned with sink error remains open: %v", err)
			}
		})
	}
}

func TestExtractionResultCloseReleasesOwnership(t *testing.T) {
	hPath, dPath := multipartSpool(t, attachment{"part.bin", []byte("payload")})
	limits := DefaultLimits()
	limits.TempDir = t.TempDir()
	result, err := ParseSpoolMessage(hPath, dPath, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(result.Close)
	if len(result.Parts) != 1 {
		t.Fatalf("parts=%d, want 1", len(result.Parts))
	}
	part := result.Parts[0]
	result.Close()
	if _, err := part.File.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("part descriptor remains open: %v", err)
	}
	if _, err := os.Stat(part.TempPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged file remains: %v", err)
	}
	if err := os.WriteFile(part.TempPath, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	result.Close()
	if got, err := os.ReadFile(part.TempPath); err != nil || string(got) != "replacement" {
		t.Fatalf("repeated Close removed a file it no longer owns: %q, %v", got, err)
	}
}

func TestExtractionHelpersCloseParts(t *testing.T) {
	for _, helper := range []string{"limits", "multipart", "encoded", "zip attachment", "zip", "tgz"} {
		var parts []ExtractedPart
		t.Run(helper, func(t *testing.T) {
			var result *ExtractionResult
			data := orderedZip(t, archiveEntry{"leaf.txt", []byte("payload")})
			switch helper {
			case "limits":
				limits := DefaultLimits()
				limits.TempDir = t.TempDir()
				result = parseWithLimits(t, "application/octet-stream", "payload", limits)
			case "multipart":
				result = parseSpoolWithCleanup(t, "multipart/mixed; boundary=b", multipartWithEncodedPart("b", "7bit", "payload"))
			case "encoded":
				result = parseEncodedSpool(t, "application/octet-stream", "7bit", "payload")
			case "zip attachment":
				result = parseZipAttachment(t, data)
			case "zip":
				result, _ = extractArchiveFixture(t, "archive.zip", data, DefaultLimits())
			case "tgz":
				data = orderedTarGz(t, archiveEntry{"leaf.txt", []byte("payload")})
				result, _ = extractArchiveFixture(t, "archive.tgz", data, DefaultLimits())
			}
			want := 1
			if helper == "zip attachment" {
				want = 2
			}
			if result.Partial || len(result.Parts) != want {
				t.Fatalf("parts=%d, want %d; partial=%v (%s)", len(result.Parts), want, result.Partial, result.PartialReason)
			}
			parts = append(parts, result.Parts...)
		})
		for _, part := range parts {
			if _, err := part.File.Stat(); !errors.Is(err, os.ErrClosed) {
				_ = part.File.Close()
				t.Errorf("%s: helper leaked descriptor for %q: %v", helper, part.Filename, err)
			}
			if _, err := os.Stat(part.TempPath); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s: helper left staged file %q: %v", helper, filepath.Base(part.TempPath), err)
			}
		}
	}
}
