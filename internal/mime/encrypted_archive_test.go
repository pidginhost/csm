package mime

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

// A password-protected ZIP is unscannable: nobody without the password can read
// its members. Go's archive/zip surfaces that in two different ways depending
// on how the archive was made, and neither used to be reported honestly.
//
//   - Legacy ZipCrypto (the "encrypt" option in Windows Explorer, WinRAR and
//     Outlook workflows) keeps the deflate method, so Open() succeeds and the
//     read fails with a decompression error. That was reported as a staging
//     failure, which sends the operator looking for a full disk.
//   - WinZip AES (7-Zip and modern WinZip) uses method 99, so Open() fails
//     with an unsupported-algorithm error. That was skipped in silence: the
//     attachment went unscanned and nothing was reported at all.
//
// Both set the encryption bit in the entry header, which is what CSM now reads.

const zipLocalHeaderSig = "PK\x03\x04"
const zipCentralHeaderSig = "PK\x01\x02"

// patchZipEntries rewrites every entry header in place. Offsets are the ones
// APPNOTE.TXT fixes for the local and central headers: the general purpose bit
// flag and the compression method.
func patchZipEntries(t *testing.T, archive []byte, setEncryptedBit bool, method uint16, wantEntries int) []byte {
	t.Helper()
	out := append([]byte(nil), archive...)
	patched := 0
	for _, header := range []struct {
		sig                string
		flagOff, methodOff int
	}{
		{zipLocalHeaderSig, 6, 8},
		{zipCentralHeaderSig, 8, 10},
	} {
		found := 0
		for i := 0; i+4 <= len(out); i++ {
			if !bytes.Equal(out[i:i+4], []byte(header.sig)) {
				continue
			}
			found++
			if setEncryptedBit {
				flags := binary.LittleEndian.Uint16(out[i+header.flagOff:])
				binary.LittleEndian.PutUint16(out[i+header.flagOff:], flags|0x1)
			}
			if method != 0xffff {
				binary.LittleEndian.PutUint16(out[i+header.methodOff:], method)
			}
		}
		if found != wantEntries {
			t.Fatalf("patched %d %q headers, want %d", found, header.sig, wantEntries)
		}
		patched += found
	}
	if patched == 0 {
		t.Fatal("no zip headers patched")
	}
	return out
}

func parseZipAttachment(t *testing.T, archive []byte) *ExtractionResult {
	t.Helper()
	body := buildMultipartBody("BOUND", "documents.zip", "application/zip", archive)
	headerPath, bodyPath := buildEximSpool(t, `multipart/mixed; boundary="BOUND"`, body)
	limits := DefaultLimits()
	limits.TempDir = t.TempDir()

	result, err := ParseSpoolMessage(headerPath, bodyPath, limits)
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	t.Cleanup(func() {
		for _, part := range result.Parts {
			_ = os.Remove(part.TempPath)
		}
	})
	return result
}

func TestEncryptedZipEntryIsReportedAsEncryptedNotPartial(t *testing.T) {
	plain := buildZipArchive(t, map[string][]byte{"Report.pdf": []byte("%PDF-1.4 report body")})
	encrypted := patchZipEntries(t, plain, true, 0xffff, 1)

	result := parseZipAttachment(t, encrypted)

	if result.Partial {
		t.Errorf("Partial = true (reason %q); an encrypted archive is permanently unscannable, not a retryable partial extraction", result.PartialReason)
	}
	if len(result.EncryptedEntries) != 1 {
		t.Fatalf("EncryptedEntries = %+v, want exactly one entry", result.EncryptedEntries)
	}
	got := result.EncryptedEntries[0]
	if got.Filename != "Report.pdf" {
		t.Errorf("Filename = %q, want Report.pdf", got.Filename)
	}
	if got.ArchiveName != "documents.zip" {
		t.Errorf("ArchiveName = %q, want documents.zip", got.ArchiveName)
	}
	for _, part := range result.Parts {
		if part.Nested {
			t.Errorf("staged a nested part %q from an encrypted archive", part.Filename)
		}
	}
}

// WinZip AES entries carry method 99 as well as the encryption bit. They must
// land on the same reported path rather than being skipped in silence.
func TestAESZipEntryIsReportedAsEncrypted(t *testing.T) {
	plain := buildZipArchive(t, map[string][]byte{"Invoice.pdf": []byte("%PDF-1.4 invoice body")})
	aes := patchZipEntries(t, plain, true, 99, 1)

	result := parseZipAttachment(t, aes)

	if len(result.EncryptedEntries) != 1 {
		t.Fatalf("EncryptedEntries = %+v, want exactly one entry", result.EncryptedEntries)
	}
	if result.EncryptedEntries[0].Filename != "Invoice.pdf" {
		t.Errorf("Filename = %q, want Invoice.pdf", result.EncryptedEntries[0].Filename)
	}
	if result.Partial {
		t.Errorf("Partial = true (reason %q), want false", result.PartialReason)
	}
}

// An entry compressed with a method Go cannot decompress is not encrypted: it
// is simply a file CSM failed to scan, and staying silent about it left the
// attachment unexamined with nothing reported.
func TestUnsupportedCompressionMethodMarksPartial(t *testing.T) {
	plain := buildZipArchive(t, map[string][]byte{"Ledger.pdf": []byte("%PDF-1.4 ledger body")})
	bzip2Entry := patchZipEntries(t, plain, false, 12, 1)

	result := parseZipAttachment(t, bzip2Entry)

	if !result.Partial {
		t.Fatal("Partial = false; an entry CSM could not decompress must be reported")
	}
	if len(result.EncryptedEntries) != 0 {
		t.Errorf("EncryptedEntries = %+v, want none for an unencrypted entry", result.EncryptedEntries)
	}
	if !strings.Contains(result.PartialReason, "Ledger.pdf") {
		t.Errorf("PartialReason = %q, want it to name the entry", result.PartialReason)
	}
	if strings.Contains(result.PartialReason, "stage") {
		t.Errorf("PartialReason = %q; the entry could not be decompressed, which is not a staging failure", result.PartialReason)
	}
}

func TestPlainZipStillExtracts(t *testing.T) {
	plain := buildZipArchive(t, map[string][]byte{"Notes.txt": []byte("plain member body")})

	result := parseZipAttachment(t, plain)

	if result.Partial {
		t.Errorf("Partial = true (reason %q), want false", result.PartialReason)
	}
	if len(result.EncryptedEntries) != 0 {
		t.Errorf("EncryptedEntries = %+v, want none", result.EncryptedEntries)
	}
	var nested int
	for _, part := range result.Parts {
		if part.Nested && part.Filename == "Notes.txt" {
			nested++
		}
	}
	if nested != 1 {
		t.Errorf("staged %d copies of the plain member, want 1", nested)
	}
}
