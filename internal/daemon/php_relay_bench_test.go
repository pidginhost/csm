package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/emailspool"
)

func BenchmarkParsePHPRelayFinding(b *testing.B) {
	cfg := defaultPHPRelayCfg()
	psw := newPerScriptWindow()
	pip := newPerIPWindow(64)
	pacct := newPerAccountWindow(5000)
	eng := newEvaluator(psw, pip, pacct, cfg, nil)
	eng.SetEffectiveAccountLimit(60)
	line := "2026-04-29 12:00:01 1abcdefghij1234-DEF <= info@example.com U=u ID=1 B=redirect_resolver"
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.parsePHPRelayAccountVolume(line, now)
	}
}

func BenchmarkSpoolHeaderRead(b *testing.B) {
	path := "../emailspool/testdata/sample_phpmailer.H"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = emailspool.ParseHeaders(path)
	}
}

func BenchmarkPerScriptWindowAppend(b *testing.B) {
	psw := newPerScriptWindow()
	s := psw.getOrCreate("k:/p")
	e := scriptEvent{At: time.Now(), MsgID: "m", FromMismatch: true, AdditionalSignal: true}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.append(e)
	}
}
