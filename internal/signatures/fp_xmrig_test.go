package signatures

import "testing"

func TestMinerXmrigBinaryRefRequiresCorroboratingContext(t *testing.T) {
	scanner := loadRepoScanner(t)
	legit := []byte(`<svg><image href="data:image/png;base64,STmiKVoXMrIGPdgLsIIf1Z"/>` +
		`<script>var RandomX=function(){this.init=function(){}};var providers=["NiceHash"];var help="--coin";</script></svg>`)
	if hasRule(scanner.ScanContent(legit, ".svg"), "miner_xmrig_binary_ref") {
		t.Error("miner_xmrig_binary_ref FP: realtime YAML rule accepted chance XMrIG plus generic mining text")
	}
	if hasRule(scanner.ScanContent([]byte("release notes mention xmr-stak as an alternative"), ".txt"), "miner_xmrig_binary_ref") {
		t.Error("miner_xmrig_binary_ref FP: realtime YAML rule accepted bare xmr-stak")
	}
}

func TestMinerXmrigBinaryRefDetectsMinerContext(t *testing.T) {
	scanner := loadRepoScanner(t)
	cases := []struct {
		name    string
		content []byte
	}{
		{
			name:    "custom pool launcher",
			content: []byte("./xmrig -o stealth-pool.example:4444 -u 48WalletAddr"),
		},
		{
			name:    "xmr-stak binary strings",
			content: []byte("\x7fELF\x02\x01\x01xmr-stak-rx\x00randomx_monero\x00pool configuration\x00"),
		},
		{
			name:    "xmrig algorithm alias",
			content: []byte("\x7fELF\x02\x01\x01xmrig\x00rx/0\x00"),
		},
		{
			name:    "official download",
			content: []byte("curl https://xmrig.com/download/xmrig-linux.tar.gz"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !hasRule(scanner.ScanContent(tc.content, ".sh"), "miner_xmrig_binary_ref") {
				t.Error("miner_xmrig_binary_ref regression: realtime YAML rule missed miner context")
			}
		})
	}
}
