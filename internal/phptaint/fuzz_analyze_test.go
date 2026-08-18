package phptaint

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

// hostileSeeds are the inputs that survived the parser spike, base64-encoded
// so no plaintext dropper is written to disk (desktop AV quarantines those).
var hostileSeeds = []string{
	base64.StdEncoding.EncodeToString([]byte("")),
	base64.StdEncoding.EncodeToString([]byte("<?php")),
	base64.StdEncoding.EncodeToString([]byte("<?php function f( {")),
	base64.StdEncoding.EncodeToString([]byte("<?php $x = 'abc")),
	base64.StdEncoding.EncodeToString([]byte("<?php /* abc")),
	base64.StdEncoding.EncodeToString([]byte("<?php $x\x00\x00 = 1;")),
	base64.StdEncoding.EncodeToString([]byte("<?php $x = '\xff\xfe\xfd';")),
	base64.StdEncoding.EncodeToString([]byte("<?php " + strings.Repeat("$a=1;", 20000))),
	base64.StdEncoding.EncodeToString([]byte("<?php $x = " + strings.Repeat("(", 50000))),
	base64.StdEncoding.EncodeToString([]byte("?>")),
}

func TestAnalyzeSurvivesHostileInput(t *testing.T) {
	for i, seed := range hostileSeeds {
		src, err := base64.StdEncoding.DecodeString(seed)
		if err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
		rep := Analyze(context.Background(), src)
		if rep.Status == StatusAnalyzed && len(rep.Results) > 0 {
			t.Errorf("seed %d reported a flow in non-flow input", i)
		}
		if rep.Status != StatusAnalyzed && len(rep.Results) != 0 {
			t.Errorf("seed %d: coverage gap carried %d results", i, len(rep.Results))
		}
	}
}

func FuzzAnalyze(f *testing.F) {
	for _, seed := range hostileSeeds {
		src, err := base64.StdEncoding.DecodeString(seed)
		if err != nil {
			continue
		}
		f.Add(src)
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		rep := Analyze(context.Background(), src)
		if rep.Status != StatusAnalyzed && len(rep.Results) != 0 {
			t.Fatalf("status %v carried %d results", rep.Status, len(rep.Results))
		}
		if len(rep.Reason) > MaxReasonBytes {
			t.Fatalf("reason %d bytes exceeds cap", len(rep.Reason))
		}
	})
}
