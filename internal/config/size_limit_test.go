package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type endlessConfigReader struct {
	bytesRead int64
}

func (r *endlessConfigReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	r.bytesRead += int64(len(p))
	return len(p), nil
}

func TestReadConfigBytesLimitedStopsAfterCap(t *testing.T) {
	reader := &endlessConfigReader{}

	_, err := readConfigBytesLimited(reader)
	if !errors.Is(err, errConfigTooLarge) {
		t.Fatalf("readConfigBytesLimited error = %v, want errConfigTooLarge", err)
	}
	if reader.bytesRead != MaxConfigBytes+1 {
		t.Fatalf("reader consumed %d bytes, want %d", reader.bytesRead, int64(MaxConfigBytes+1))
	}
}

func TestLoadBytesRejectsInputOverCap(t *testing.T) {
	_, err := LoadBytes(bytes.Repeat([]byte(" "), MaxConfigBytes+1))
	if err == nil {
		t.Fatal("LoadBytes must reject input over MaxConfigBytes")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("LoadBytes error = %v, want size-cap refusal", err)
	}
}

func TestLoadRejectsMainConfigOverCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	must(t, os.WriteFile(path, bytes.Repeat([]byte(" "), MaxConfigBytes+1), 0o600))

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load must reject a main config over MaxConfigBytes")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Load error = %v, want size-cap refusal", err)
	}
}

func TestLoadWithDirRejectsMainConfigOverCap(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "csm.yaml")
	confd := filepath.Join(dir, "conf.d")
	must(t, os.MkdirAll(confd, 0o700))
	must(t, os.WriteFile(main, bytes.Repeat([]byte(" "), MaxConfigBytes+1), 0o600))

	_, err := LoadWithDir(main, confd)
	if err == nil {
		t.Fatal("LoadWithDir must reject a main config over MaxConfigBytes")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("LoadWithDir error = %v, want size-cap refusal", err)
	}
}

func TestLoadConfDirRejectsFragmentOverCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "10-too-large.yaml")
	must(t, os.WriteFile(path, bytes.Repeat([]byte(" "), MaxConfigBytes+1), 0o600))

	_, err := LoadConfDir(dir)
	if err == nil {
		t.Fatal("LoadConfDir must reject a fragment over MaxConfigBytes")
	}
	if !strings.Contains(err.Error(), "conf.d fragment") || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("LoadConfDir error = %v, want fragment size-cap refusal", err)
	}
}
