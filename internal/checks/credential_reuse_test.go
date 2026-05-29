package checks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/mysqlclient"
)

func TestHashFingerprintGroupsIdenticalNeverLeaksHash(t *testing.T) {
	raw := "$P$Bxxxxxxxxxxxxxxxxxxxxxxxxxxx" // synthetic phpass-shaped hash
	fp1 := credentialHashFingerprint(raw)
	fp2 := credentialHashFingerprint(raw)
	if fp1 == "" || fp1 != fp2 {
		t.Fatalf("identical hashes must map to the same non-empty fingerprint: %q vs %q", fp1, fp2)
	}
	if credentialHashFingerprint("") != "" {
		t.Error("empty hash must yield empty fingerprint")
	}
	if credentialHashFingerprint("other") == fp1 {
		t.Error("distinct hashes must not collide")
	}
	// The fingerprint must not reveal the raw hash.
	if strings.Contains(fp1, raw) || strings.Contains(fp1, "$P$") {
		t.Errorf("fingerprint leaks the raw hash: %q", fp1)
	}
	if !strings.HasPrefix(fp1, "fp:") {
		t.Errorf("fingerprint prefix = %q, want fp:", fp1)
	}
	if len(strings.TrimPrefix(fp1, "fp:")) != 16 {
		t.Errorf("fingerprint length = %d hex chars, want 16", len(strings.TrimPrefix(fp1, "fp:")))
	}
}

func TestBuildCredentialReuseFindings(t *testing.T) {
	byFingerprint := map[string]map[string]struct{}{
		"fp:z-secret": {"erin": {}, "frank": {}},
		"fp:single":   {"dave": {}},
		"fp:a-secret": {"alice": {}, "bob": {}, "carol": {}},
	}
	out := buildCredentialReuseFindings(byFingerprint, credentialReuseMinAccounts)
	if len(out) != 2 {
		t.Fatalf("findings = %d, want 2 (only fingerprints on >=2 accounts)", len(out))
	}
	// Deterministic order is based on the emitted account list, not the
	// secret-derived fingerprint.
	if !strings.Contains(out[0].Message, "alice, bob, carol") {
		t.Errorf("first finding accounts wrong: %q", out[0].Message)
	}
	if !strings.Contains(out[1].Message, "erin, frank") {
		t.Errorf("second finding accounts wrong: %q", out[1].Message)
	}
	if out[0].Check != "credential_reuse" {
		t.Errorf("check = %q", out[0].Check)
	}
	// No finding may contain a raw fingerprint key.
	for _, f := range out {
		if strings.Contains(f.Message, "fp:") || strings.Contains(f.Details, "fp:") {
			t.Errorf("finding leaks fingerprint key: %q / %q", f.Message, f.Details)
		}
	}
}

func TestBuildCredentialReuseFindingsEmpty(t *testing.T) {
	if out := buildCredentialReuseFindings(nil, 2); len(out) != 0 {
		t.Errorf("nil input -> %d findings, want 0", len(out))
	}
	single := map[string]map[string]struct{}{"fp:x": {"alice": {}}}
	if out := buildCredentialReuseFindings(single, 2); len(out) != 0 {
		t.Errorf("single-account hash must not flag: %d", len(out))
	}
}

func TestAdminPasswordFingerprintsForSiteUsesRootQuery(t *testing.T) {
	const raw = "$P$Bsharedwordpresshashxxxxxxxx"
	var gotSchema, gotQuery string
	mysqlclient.SetRootQueryForTest(func(_ context.Context, schema, query string, _ ...any) ([]string, error) {
		gotSchema = schema
		gotQuery = query
		return []string{" " + raw + " ", ""}, nil
	})
	t.Cleanup(func() { mysqlclient.SetRootQueryForTest(nil) })

	out := adminPasswordFingerprintsForSite(wpDBCreds{dbName: "alice_wp"}, "wp_")
	if gotSchema != "alice_wp" {
		t.Fatalf("schema = %q, want alice_wp", gotSchema)
	}
	for _, want := range []string{
		"SELECT DISTINCT u.user_pass",
		"FROM `wp_users` u",
		"JOIN `wp_usermeta` um ON u.ID = um.user_id",
		"um.meta_key = 'wp_capabilities'",
		"um.meta_value LIKE '%administrator%'",
	} {
		if !strings.Contains(gotQuery, want) {
			t.Fatalf("query missing %q: %s", want, gotQuery)
		}
	}
	if len(out) != 1 || out[0] != credentialHashFingerprint(raw) {
		t.Fatalf("fingerprints = %#v, want one fingerprint for raw hash", out)
	}
	if strings.Contains(strings.Join(out, ","), raw) {
		t.Fatalf("fingerprint output leaked raw hash: %#v", out)
	}
}

func TestCheckCredentialReuseScansHostAndDoesNotLeakHash(t *testing.T) {
	const raw = "$P$Bsharedwordpresshashxxxxxxxx"
	const distinct = "$P$Bdistinctwordpresshashxxxxxx"
	files := map[string]string{}
	for _, account := range []string{"alice", "bob", "carol"} {
		path := "/home/" + account + "/public_html/wp-config.php"
		tmp := t.TempDir() + "/" + account + ".php"
		dbName := account + "_wp"
		if err := os.WriteFile(tmp, []byte("<?php\n"+
			"define('DB_NAME', '"+dbName+"');\n"+
			"$table_prefix = 'wp_';\n"), 0600); err != nil {
			t.Fatalf("write wp-config fixture: %v", err)
		}
		files[path] = tmp
	}

	oldOS := osFS
	osFS = &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern != "/home/*/public_html/wp-config.php" {
				t.Fatalf("glob pattern = %q", pattern)
			}
			return []string{
				"/home/alice/public_html/wp-config.php",
				"/home/bob/public_html/wp-config.php",
				"/home/carol/public_html/wp-config.php",
			}, nil
		},
		open: func(name string) (*os.File, error) {
			return os.Open(files[name])
		},
	}
	t.Cleanup(func() { osFS = oldOS })

	mysqlclient.SetRootQueryForTest(func(_ context.Context, schema, _ string, _ ...any) ([]string, error) {
		switch schema {
		case "alice_wp", "bob_wp":
			return []string{raw}, nil
		case "carol_wp":
			return []string{distinct}, nil
		default:
			t.Fatalf("unexpected schema %q", schema)
		}
		return nil, nil
	})
	t.Cleanup(func() { mysqlclient.SetRootQueryForTest(nil) })

	findings := CheckCredentialReuse(context.Background(), nil, nil)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
	}
	findingText := findings[0].Message + "\n" + findings[0].Details
	for _, want := range []string{"alice", "bob"} {
		if !strings.Contains(findingText, want) {
			t.Fatalf("finding missing account %q: %s", want, findingText)
		}
	}
	if strings.Contains(findingText, "carol") {
		t.Fatalf("single-account hash should not flag carol: %s", findingText)
	}
	for _, secret := range []string{raw, distinct, credentialHashFingerprint(raw), credentialHashFingerprint(distinct)} {
		if strings.Contains(findingText, secret) {
			t.Fatalf("finding leaked secret %q: %s", secret, findingText)
		}
	}
}

func TestCheckCredentialReuseRejectsUnsafeTablePrefix(t *testing.T) {
	wpConfig := "/home/alice/public_html/wp-config.php"
	tmp := t.TempDir() + "/wp-config.php"
	if err := os.WriteFile(tmp, []byte("<?php\n"+
		"define('DB_NAME', 'alice_wp');\n"+
		"$table_prefix = 'wp_`bad';\n"), 0600); err != nil {
		t.Fatalf("write wp-config fixture: %v", err)
	}

	oldOS := osFS
	osFS = &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern != "/home/*/public_html/wp-config.php" {
				t.Fatalf("glob pattern = %q", pattern)
			}
			return []string{wpConfig}, nil
		},
		open: func(name string) (*os.File, error) {
			if name != wpConfig {
				t.Fatalf("open path = %q, want %q", name, wpConfig)
			}
			return os.Open(tmp)
		},
	}
	t.Cleanup(func() { osFS = oldOS })

	mysqlclient.SetRootQueryForTest(func(_ context.Context, _, query string, _ ...any) ([]string, error) {
		t.Fatalf("unsafe table prefix reached MySQL query: %s", query)
		return nil, nil
	})
	t.Cleanup(func() { mysqlclient.SetRootQueryForTest(nil) })

	if findings := CheckCredentialReuse(context.Background(), nil, nil); len(findings) != 0 {
		t.Fatalf("unsafe prefix findings = %+v, want none", findings)
	}
}
