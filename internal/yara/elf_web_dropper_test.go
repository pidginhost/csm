//go:build yara

package yara

import (
	"encoding/binary"
	"testing"
)

// elfKind selects how buildTestELF marks the image. The rule must tell a
// program apart from a library by the same fields the kernel and the dynamic
// loader read, never by file name or location.
type elfKind int

const (
	elfStaticExec   elfKind = iota // ET_EXEC, as a static non-PIE build produces
	elfPIE                         // ET_DYN with PT_INTERP and no DF_1_PIE, as older linkers emit
	elfStaticPIE                   // ET_DYN without PT_INTERP, DF_1_PIE in DT_FLAGS_1
	elfSharedObject                // ET_DYN with a dynamic section but no PT_INTERP or DF_1_PIE
)

// buildTestELF returns a minimal little-endian ELF64 image: header, program
// headers, the segments they point at, then payload. It is assembled in memory
// so no executable fixture is ever written to disk.
func buildTestELF(kind elfKind, payload string) []byte {
	const (
		ehdrSize  = 64
		phdrSize  = 56
		ptLoad    = 1
		ptDynamic = 2
		ptInterp  = 3
		dtNull    = 0
		dtFlags1  = 0x6ffffffb
		df1PIE    = 0x08000000
		df1NoDel  = 0x00000008
	)
	etype := uint16(3)
	if kind == elfStaticExec {
		etype = 2
	}
	interp := kind == elfPIE
	dynamic := kind == elfStaticPIE || kind == elfSharedObject
	phnum := 1
	if interp {
		phnum++
	}
	if dynamic {
		phnum++
	}

	interpPath := []byte("/lib64/ld-linux-x86-64.so.2\x00")
	off := ehdrSize + phnum*phdrSize
	interpOff := off
	if interp {
		off += len(interpPath)
	}
	dynOff := off
	if dynamic {
		off += 2 * 16
	}
	payloadOff := off
	size := payloadOff + len(payload)

	img := make([]byte, size)
	le := binary.LittleEndian
	copy(img, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	le.PutUint16(img[16:], etype)
	le.PutUint16(img[18:], 62) // EM_X86_64
	le.PutUint32(img[20:], 1)
	le.PutUint64(img[24:], 0x401000)
	le.PutUint64(img[32:], ehdrSize)
	le.PutUint16(img[52:], ehdrSize)
	le.PutUint16(img[54:], phdrSize)
	le.PutUint16(img[56:], uint16(phnum))

	phdr := func(i int, ptype uint32, offset, filesz int) {
		p := img[ehdrSize+i*phdrSize:]
		le.PutUint32(p[0:], ptype)
		le.PutUint32(p[4:], 5) // PF_R|PF_X
		le.PutUint64(p[8:], uint64(offset))
		le.PutUint64(p[16:], 0x400000+uint64(offset))
		le.PutUint64(p[24:], 0x400000+uint64(offset))
		le.PutUint64(p[32:], uint64(filesz))
		le.PutUint64(p[40:], uint64(filesz))
		le.PutUint64(p[48:], 0x1000)
	}
	next := 0
	phdr(next, ptLoad, 0, size)
	next++
	if interp {
		phdr(next, ptInterp, interpOff, len(interpPath))
		copy(img[interpOff:], interpPath)
		next++
	}
	if dynamic {
		phdr(next, ptDynamic, dynOff, 2*16)
		le.PutUint64(img[dynOff:], dtFlags1)
		flags := uint64(df1NoDel)
		if kind == elfStaticPIE {
			flags |= df1PIE
		}
		le.PutUint64(img[dynOff+8:], flags)
		le.PutUint64(img[dynOff+16:], dtNull)
	}
	copy(img[payloadOff:], payload)
	return img
}

// Strings a downloader program carries. Native code keeps literals
// NUL-terminated in its read-only data, so each one is written that way.
const (
	wgetTemplate  = "wget -q --no-check-certificate -O '\x00"
	curlTemplate  = "curl -s -k -o '\x00"
	phpPayloadURL = "https://dl.example.net/kit/loader.php\x00"
	htaccessURL   = "https://dl.example.net/kit/.htaccess\x00"
	phpWriter     = "<?php\n$d = file_get_contents($argv[1]);\nfile_put_contents($argv[2], $d);\n\x00"
	archiveURL    = "https://downloads.example.org/tool/tool-linux-amd64.tar.gz\x00"
	apiURL        = "https://api.example.org/v1/license/check.php\x00"
)

func TestELFWebPayloadDropperRule(t *testing.T) {
	s := loadRepoYaraScanner(t)
	const rule = "elf_web_payload_dropper"

	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"static program fetching a PHP payload with wget", buildTestELF(elfStaticExec, wgetTemplate+phpPayloadURL), true},
		{"static program fetching an .htaccess with wget", buildTestELF(elfStaticExec, wgetTemplate+htaccessURL), true},
		{"static program writing embedded PHP fetched with curl", buildTestELF(elfStaticExec, curlTemplate+phpWriter+archiveURL), true},
		{"dynamic PIE program fetching a PHP payload", buildTestELF(elfPIE, curlTemplate+phpPayloadURL), true},
		{"static PIE program fetching a PHP payload", buildTestELF(elfStaticPIE, wgetTemplate+phpPayloadURL), true},

		// A shared library is not a program, whatever strings it carries.
		{"shared object with the same strings", buildTestELF(elfSharedObject, wgetTemplate+phpPayloadURL+phpWriter), false},
		// Vendor tools legitimately call PHP endpoints and download archives.
		{"program with a PHP URL and PHP writer but no download template", buildTestELF(elfStaticExec, apiURL+phpWriter), false},
		{"program downloading an archive with wget", buildTestELF(elfStaticExec, wgetTemplate+archiveURL), false},
		{"download template alone", buildTestELF(elfPIE, wgetTemplate+curlTemplate), false},
		// The rule judges native programs; scripts are covered by other rules.
		{"shell script with the same strings", []byte("#!/bin/sh\n" + wgetTemplate + phpPayloadURL), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hasYaraRule(s.ScanBytes(tc.data), rule)
			if got != tc.want {
				t.Fatalf("%s matched=%v, want %v", rule, got, tc.want)
			}
		})
	}
}
