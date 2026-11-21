package platform

import (
	"os"
	"path/filepath"
	"testing"
)

// LiteSpeed runs PHP as its own user when PHP suEXEC is off; site code then
// writes what the server writes. A setting CSM cannot read counts as off.
func TestLiteSpeedRunsPHPAsServer(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name, xml string
		want      bool
	}{
		{"suexec off", "<httpServerConfig><phpSuExec>0</phpSuExec></httpServerConfig>", true},
		{"suexec on", "<httpServerConfig><phpSuExec>1</phpSuExec></httpServerConfig>", false},
		{"home directories only", "<httpServerConfig>\n  <phpSuExec> 2 </phpSuExec>\n</httpServerConfig>", false},
		{"unknown value", "<httpServerConfig><phpSuExec>3</phpSuExec></httpServerConfig>", true},
		{"missing", "<httpServerConfig><user>nobody</user></httpServerConfig>", true},
		{"twice", "<httpServerConfig><phpSuExec>1</phpSuExec><phpSuExec>0</phpSuExec></httpServerConfig>", true},
		{"other document", "<vhostConfig><phpSuExec>1</phpSuExec></vhostConfig>", true},
		{"second document", "<httpServerConfig><phpSuExec>1</phpSuExec></httpServerConfig><httpServerConfig><phpSuExec>0</phpSuExec></httpServerConfig>", true},
		{"trailing setting", "<httpServerConfig><phpSuExec>1</phpSuExec></httpServerConfig><phpSuExec>0</phpSuExec>", true},
		{"trailing garbage", "<httpServerConfig><phpSuExec>1</phpSuExec></httpServerConfig>garbage", true},
		{"nested value", "<httpServerConfig><phpSuExec>1<phpSuExec>0</phpSuExec></phpSuExec></httpServerConfig>", true},
		{"namespaced setting", "<httpServerConfig xmlns:x='urn:example'><x:phpSuExec>1</x:phpSuExec></httpServerConfig>", true},
		{"malformed", "<httpServerConfig><phpSuExec>1</phpSuExec>", true},
	} {
		path := filepath.Join(dir, tc.name+".xml")
		if err := os.WriteFile(path, []byte(tc.xml), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := liteSpeedRunsPHPAsServer(path); got != tc.want {
			t.Errorf("%s: liteSpeedRunsPHPAsServer = %v, want %v", tc.name, got, tc.want)
		}
	}
	if !liteSpeedRunsPHPAsServer(filepath.Join(dir, "absent.xml")) {
		t.Error("an unreadable configuration was trusted")
	}
}

// A web_server override that selects LiteSpeed reads its suEXEC setting too;
// one that selects Apache clears it.
func TestOverrideRecomputesServerRunsSiteCode(t *testing.T) {
	lsws, apache := WSLiteSpeed, WSApache
	got := applyOverrides(Info{WebServer: WSApache}, Overrides{WebServer: &lsws})
	if want := liteSpeedRunsPHPAsServer(LiteSpeedConfigPath); got.ServerRunsSiteCode != want {
		t.Fatalf("override to LiteSpeed: ServerRunsSiteCode = %v, want %v", got.ServerRunsSiteCode, want)
	}
	if got := applyOverrides(Info{WebServer: WSLiteSpeed, ServerRunsSiteCode: true}, Overrides{WebServer: &apache}); got.ServerRunsSiteCode {
		t.Fatal("override to Apache kept LiteSpeed's suEXEC state")
	}
}
