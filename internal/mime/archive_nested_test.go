package mime

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func TestZipInZipAtDefaultDepthIsPartial(t *testing.T) {
	inner := buildZipArchive(t, map[string][]byte{"evil.txt": []byte("payload")})
	outer := buildZipArchive(t, map[string][]byte{"inner.zip": inner})
	body := buildMultipartBody("BOUND", "outer.zip", "application/zip", outer)
	r := parseWithLimits(t, `multipart/mixed; boundary="BOUND"`, body, DefaultLimits()) // depth 1
	if !r.Partial || !strings.Contains(r.PartialReason, `nested archive "inner.zip" not expanded`) {
		t.Fatalf("Partial=%v reason=%q", r.Partial, r.PartialReason)
	}
	for _, p := range r.Parts {
		if p.Filename == "evil.txt" {
			t.Fatal("expanded past max_archive_depth")
		}
	}
}

func TestZipInZipWithinDepthIsExpanded(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxArchiveDepth = 2
	limits.TempDir = t.TempDir()
	inner := buildTarGzArchive(t, map[string][]byte{"../../evil\n.txt": []byte("payload")})
	outer := buildZipArchive(t, map[string][]byte{"dir/inner.tar.gz": inner})
	body := buildMultipartBody("BOUND", "outer.zip", "application/zip", outer)
	r := parseWithLimits(t, `multipart/mixed; boundary="BOUND"`, body, limits)
	if r.Partial {
		t.Fatalf("partial within depth: %q", r.PartialReason)
	}
	var found bool
	for _, p := range r.Parts {
		if p.Filename == "evil" && p.Nested && p.ArchiveName == "inner.tar.gz" {
			found = true // name sanitised: base name, cut at the control character
		}
	}
	if !found {
		t.Fatalf("inner member missing or unsanitised: %+v", r.Parts)
	}
	for _, p := range r.Parts {
		_ = os.Remove(p.TempPath)
	}
	requireTempDirEmpty(t, limits.TempDir)
}

func TestDepthLimitStopsDeeperArchives(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxArchiveDepth = 2
	l3 := buildZipArchive(t, map[string][]byte{"deep.txt": []byte("x")})
	l2 := buildZipArchive(t, map[string][]byte{"l3.zip": l3})
	l1 := buildZipArchive(t, map[string][]byte{"l2.zip": l2})
	body := buildMultipartBody("BOUND", "l1.zip", "application/zip", l1)
	r := parseWithLimits(t, `multipart/mixed; boundary="BOUND"`, body, limits)
	if !r.Partial || !strings.Contains(r.PartialReason, `nested archive "l3.zip" not expanded`) {
		t.Fatalf("Partial=%v reason=%q", r.Partial, r.PartialReason)
	}
}

func TestSinglePartZipMessageIsExpanded(t *testing.T) {
	zipBytes := buildZipArchive(t, map[string][]byte{"x.txt": []byte("inside")})
	body := base64.StdEncoding.EncodeToString(zipBytes)
	r := parseEncodedSpool(t, `application/zip; name="a.zip"`, "base64", body)
	var found bool
	for _, p := range r.Parts {
		found = found || (p.Filename == "x.txt" && p.Nested)
	}
	if !found {
		t.Fatalf("single-part zip not expanded: %+v", r.Parts)
	}
}
