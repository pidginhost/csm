package checks

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// --- CheckWPBruteForce -----------------------------------------------

func TestCheckWPBruteForceNoLogs(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckWPBruteForce(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no logs should produce 0, got %d", len(findings))
	}
}

// --- CheckNulledPlugins -----------------------------------------------

func TestCheckNulledPluginsNoHome(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckNulledPlugins(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no home should produce 0, got %d", len(findings))
	}
}

// --- CheckMailPerAccount ----------------------------------------------

func TestCheckMailPerAccountNoExim(t *testing.T) {
	withMockCmd(t, &mockCmd{})
	findings := CheckMailPerAccount(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no exim should produce 0, got %d", len(findings))
	}
}

// --- CheckLocalThreatScore -------------------------------------------

func TestCheckLocalThreatScoreNoAttackDB(t *testing.T) {
	findings := CheckLocalThreatScore(context.Background(), &config.Config{}, nil)
	// Without global attackDB, returns nil
	if len(findings) != 0 {
		t.Errorf("no attackdb should produce 0, got %d", len(findings))
	}
}

// --- CheckOpenBasedir ------------------------------------------------

func TestCheckOpenBasedirNoHome(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckOpenBasedir(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no home should produce 0, got %d", len(findings))
	}
}

// --- CheckSymlinkAttacks ---------------------------------------------

func TestCheckSymlinkAttacksNoHome(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckSymlinkAttacks(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no home should produce 0, got %d", len(findings))
	}
}

// --- CheckDNSZoneChanges ---------------------------------------------

func TestCheckDNSZoneChangesNoCmd(t *testing.T) {
	withMockCmd(t, &mockCmd{})
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	findings := CheckDNSZoneChanges(context.Background(), &config.Config{}, store)
	if len(findings) != 0 {
		t.Errorf("no cmd should produce 0, got %d", len(findings))
	}
}

// --- CheckSSLCertIssuance --------------------------------------------

func TestCheckSSLCertIssuanceNoCmd(t *testing.T) {
	withMockCmd(t, &mockCmd{})
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	findings := CheckSSLCertIssuance(context.Background(), &config.Config{}, store)
	if len(findings) != 0 {
		t.Errorf("no cmd should produce 0, got %d", len(findings))
	}
}

// --- CheckWAFStatus --------------------------------------------------

func TestCheckWAFStatusNoConfigs(t *testing.T) {
	withMockOS(t, &mockOS{})
	withMockCmd(t, &mockCmd{})
	findings := CheckWAFStatus(context.Background(), &config.Config{}, nil)
	// Without WAF configs, may produce a warning.
	_ = findings
}

// --- CheckModSecAuditLog ---------------------------------------------

func TestCheckModSecAuditLogNoLog(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckModSecAuditLog(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no audit log should produce 0, got %d", len(findings))
	}
}

// --- CheckFileIndex --------------------------------------------------

func TestCheckFileIndexNoHome(t *testing.T) {
	withMockOS(t, &mockOS{})
	cfg := &config.Config{StatePath: t.TempDir()}
	findings := CheckFileIndex(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Errorf("no home should produce 0, got %d", len(findings))
	}
}

// --- CheckPhishing ---------------------------------------------------

func TestCheckPhishingNoHome(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckPhishing(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no home should produce 0, got %d", len(findings))
	}
}

// --- CheckPHPContent -------------------------------------------------

func TestCheckPHPContentNoHome(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckPHPContent(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no home should produce 0, got %d", len(findings))
	}
}

// --- CheckFilesystem -------------------------------------------------

func TestCheckFilesystemNoGlob(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckFilesystem(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no glob should produce 0, got %d", len(findings))
	}
}

// --- CheckWebshells --------------------------------------------------

func TestCheckWebshellsNoHome(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckWebshells(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no home should produce 0, got %d", len(findings))
	}
}

// --- CheckHtaccess ---------------------------------------------------

func TestCheckHtaccessNoHome(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckHtaccess(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no home should produce 0, got %d", len(findings))
	}
}

// --- CheckPHPConfigChanges -------------------------------------------

func TestCheckPHPConfigChangesNoGlob(t *testing.T) {
	withMockOS(t, &mockOS{})
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	findings := CheckPHPConfigChanges(context.Background(), &config.Config{}, store)
	if len(findings) != 0 {
		t.Errorf("no glob should produce 0, got %d", len(findings))
	}
}

// --- CheckCpanelLogins -----------------------------------------------

func TestCheckCpanelLoginsNoLog(t *testing.T) {
	withMockOS(t, &mockOS{})
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	findings := CheckCpanelLogins(context.Background(), &config.Config{}, store)
	if len(findings) != 0 {
		t.Errorf("no log should produce 0, got %d", len(findings))
	}
}

// --- CheckCpanelFileManager ------------------------------------------

func TestCheckCpanelFileManagerNoLog(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckCpanelFileManager(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no log should produce 0, got %d", len(findings))
	}
}

// --- CheckSSHKeys ----------------------------------------------------

func TestCheckSSHKeysNoHome(t *testing.T) {
	withMockOS(t, &mockOS{})
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	findings := CheckSSHKeys(context.Background(), &config.Config{}, store)
	if len(findings) != 0 {
		t.Errorf("no home should produce 0, got %d", len(findings))
	}
}

// --- CheckAPITokens --------------------------------------------------

func TestCheckAPITokensNoGlob(t *testing.T) {
	withMockOS(t, &mockOS{})
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	findings := CheckAPITokens(context.Background(), &config.Config{}, store)
	if len(findings) != 0 {
		t.Errorf("no glob should produce 0, got %d", len(findings))
	}
}

// --- CheckDatabaseContent --------------------------------------------

func TestCheckDatabaseContentNoHome(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckDatabaseContent(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no home should produce 0, got %d", len(findings))
	}
}

// --- CheckForwarders -------------------------------------------------

func TestCheckForwardersNoValiases(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckForwarders(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no valiases should produce 0, got %d", len(findings))
	}
}

// --- CheckOutdatedPlugins --------------------------------------------

func TestCheckOutdatedPluginsNoHome(t *testing.T) {
	withMockOS(t, &mockOS{})
	withMockCmd(t, &mockCmd{})
	findings := CheckOutdatedPlugins(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no home should produce 0, got %d", len(findings))
	}
}

// --- CheckOutboundEmailContent ---------------------------------------

func TestCheckOutboundEmailContentNoSpool(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckOutboundEmailContent(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no spool should produce 0, got %d", len(findings))
	}
}

// --- CheckEmailPasswords ---------------------------------------------

func TestCheckEmailPasswordsNoShadow(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckEmailPasswords(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no shadow should produce 0, got %d", len(findings))
	}
}

// --- Performance checks ----------------------------------------------

func TestCheckLoadAverageNoProc(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckLoadAverage(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no /proc should produce 0, got %d", len(findings))
	}
}

func TestCheckPHPProcessLoadNoProc(t *testing.T) {
	withMockOS(t, &mockOS{})
	withMockCmd(t, &mockCmd{})
	findings := CheckPHPProcessLoad(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no /proc should produce 0, got %d", len(findings))
	}
}

func TestCheckSwapAndOOMNoProc(t *testing.T) {
	withMockOS(t, &mockOS{})
	withMockCmd(t, &mockCmd{})
	findings := CheckSwapAndOOM(context.Background(), &config.Config{}, nil)
	_ = findings // exercises the function
}

func TestCheckMySQLConfigNoCmd(t *testing.T) {
	withMockCmd(t, &mockCmd{})
	withMockOS(t, &mockOS{})
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	findings := CheckMySQLConfig(context.Background(), &config.Config{}, store)
	if len(findings) != 0 {
		t.Errorf("no mysql should produce 0, got %d", len(findings))
	}
}

func TestCheckRedisConfigNoCmd(t *testing.T) {
	withMockCmd(t, &mockCmd{})
	withMockOS(t, &mockOS{})
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	findings := CheckRedisConfig(context.Background(), &config.Config{}, store)
	if len(findings) != 0 {
		t.Errorf("no redis should produce 0, got %d", len(findings))
	}
}

func TestCheckErrorLogBloatNoHome(t *testing.T) {
	withMockOS(t, &mockOS{})
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	findings := CheckErrorLogBloat(context.Background(), &config.Config{}, store)
	if len(findings) != 0 {
		t.Errorf("no home should produce 0, got %d", len(findings))
	}
}

func TestCheckWPConfigNoHome(t *testing.T) {
	withMockOS(t, &mockOS{})
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	findings := CheckWPConfig(context.Background(), &config.Config{}, store)
	if len(findings) != 0 {
		t.Errorf("no home should produce 0, got %d", len(findings))
	}
}

func TestCheckWPTransientBloatNoHome(t *testing.T) {
	withMockOS(t, &mockOS{})
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	findings := CheckWPTransientBloat(context.Background(), &config.Config{}, store)
	if len(findings) != 0 {
		t.Errorf("no home should produce 0, got %d", len(findings))
	}
}

func TestCheckWPCronNoHome(t *testing.T) {
	withMockOS(t, &mockOS{})
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	findings := CheckWPCron(context.Background(), &config.Config{}, store)
	if len(findings) != 0 {
		t.Errorf("no home should produce 0, got %d", len(findings))
	}
}

func TestCheckPHPHandlerNoHome(t *testing.T) {
	withMockOS(t, &mockOS{})
	withMockCmd(t, &mockCmd{})
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	findings := CheckPHPHandler(context.Background(), &config.Config{}, store)
	if len(findings) != 0 {
		t.Errorf("no home should produce 0, got %d", len(findings))
	}
}
