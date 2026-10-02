package checks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mysqlclient"
)

// MyISAM locks a whole table for every write. On a busy WordPress site a burst
// of uncached requests queues behind those locks, holds every database
// connection the account is allowed, and the site answers with database
// errors. InnoDB locks rows, so the same burst does not take the site down.

// myisamHost is a fake cPanel host: wp-config.php files under account homes,
// the panel's domain map, and suspended accounts.
type myisamHost struct {
	servedRootsFS
	t          *testing.T
	configs    map[string]string
	unreadable map[string]bool
	suspended  map[string]bool
}

func (h *myisamHost) Open(name string) (*os.File, error) {
	if h.unreadable[name] {
		return nil, os.ErrPermission
	}
	body, ok := h.configs[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	path := filepath.Join(h.t.TempDir(), "wp-config.php")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return nil, err
	}
	return os.Open(path)
}

func (h *myisamHost) Stat(name string) (os.FileInfo, error) {
	if account, ok := strings.CutPrefix(name, "/var/cpanel/suspended/"); ok && h.suspended[account] {
		return fakeFileInfo{name: account}, nil
	}
	return nil, os.ErrNotExist
}

// withMyISAMHost installs the fake host. served lists the document roots the
// panel maps; any other install is dormant once the map names at least one
// root (an empty map leaves every install's state unknown).
func withMyISAMHost(t *testing.T, configs map[string]string, served ...string) *myisamHost {
	t.Helper()
	var domainMap strings.Builder
	for i, root := range served {
		account := strings.Split(root, "/")[2]
		domain := account + string(rune('a'+i)) + ".example"
		domainMap.WriteString(domain + ": " + account + "==root==main==" + domain + "==" + root + "==192.0.2.10:80\n")
	}
	files := make([]string, 0, len(configs))
	for path := range configs {
		files = append(files, path)
	}
	host := &myisamHost{
		servedRootsFS: servedRootsFS{
			mockOSGlobRoots: mockOSGlobRoots{files: files},
			domainMap:       domainMap.String(),
		},
		t:          t,
		configs:    configs,
		unreadable: map[string]bool{},
		suspended:  map[string]bool{},
	}
	withMockOS(t, host)
	return host
}

func wpConfigFor(db, host, prefix string) string {
	return "<?php\n" +
		"define('DB_NAME', '" + db + "');\n" +
		"define('DB_USER', '" + db + "');\n" +
		"define('DB_PASSWORD', 'unused');\n" +
		"define('DB_HOST', '" + host + "');\n" +
		"$table_prefix = '" + prefix + "';\n"
}

// withMyISAMTables answers the root catalogue query with rows of
// schema, table and on-disk bytes, as MySQL reports them.
func withMyISAMTables(t *testing.T, rows ...string) *int {
	t.Helper()
	calls := 0
	mysqlclient.SetRootQueryForTest(func(_ context.Context, _ string, query string, _ ...any) ([]string, error) {
		if !strings.Contains(query, "information_schema.TABLES") {
			return nil, errors.New("unexpected query: " + query)
		}
		calls++
		return rows, nil
	})
	t.Cleanup(func() { mysqlclient.SetRootQueryForTest(nil) })
	return &calls
}

func TestCheckWPMyISAM_ReportsServedInstallWithMyISAMTables(t *testing.T) {
	const cfgPath = "/home/alice/public_html/wp-config.php"
	withMyISAMHost(t, map[string]string{cfgPath: wpConfigFor("alice_wp", "localhost", "wp_")},
		"/home/alice/public_html")
	withMyISAMTables(t,
		"alice_wp\twp_options\t1048576",
		"alice_wp\twp_postmeta\t47185920",
		"alice_wp\twp_2_posts\t524288",
		"bob_wp\twp_posts\t9999999",
	)

	findings := CheckWPMyISAM(context.Background(), &config.Config{}, nil)

	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Check != "perf_wp_myisam" || f.Severity != alert.Warning {
		t.Fatalf("check/severity = %s/%v, want perf_wp_myisam/Warning", f.Check, f.Severity)
	}
	if !strings.Contains(f.Message, "alice") {
		t.Errorf("message does not name the account: %q", f.Message)
	}
	for _, want := range []string{"Database: alice_wp,", "prefix: wp_,", "MyISAM tables: 3 (46M)", cfgPath} {
		if !strings.Contains(f.Details, want) {
			t.Errorf("details missing %q: %q", want, f.Details)
		}
	}
	postmeta := strings.Index(f.Details, "wp_postmeta")
	options := strings.Index(f.Details, "wp_options")
	subsite := strings.Index(f.Details, "wp_2_posts")
	if postmeta < 0 || options < 0 || subsite < 0 || postmeta >= options || options >= subsite {
		t.Errorf("tables not listed largest first: %q", f.Details)
	}
	if strings.Contains(f.Details, "bob_wp") {
		t.Errorf("another database's tables were attributed to this install: %q", f.Details)
	}
}

func TestCheckWPMyISAM_NoFindingWhenInstallTablesAreInnoDB(t *testing.T) {
	withMyISAMHost(t, map[string]string{
		"/home/alice/public_html/wp-config.php": wpConfigFor("alice_wp", "localhost", "wp_"),
	}, "/home/alice/public_html")
	calls := withMyISAMTables(t, "bob_wp\twp_posts\t4096")

	findings := CheckWPMyISAM(context.Background(), &config.Config{}, nil)

	if *calls != 1 {
		t.Fatalf("catalogue queried %d times, want 1", *calls)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

// Two installs can share one database under different table prefixes. A
// table belongs to the install with the longest matching prefix, so the
// shop's tables are never reported against the main site, even when the
// shop itself is not reported.
func TestCheckWPMyISAM_AttributesTablesToLongestPrefix(t *testing.T) {
	const (
		mainCfg = "/home/alice/public_html/wp-config.php"
		shopCfg = "/home/alice/shop.example/wp-config.php"
	)
	for _, tc := range []struct {
		name     string
		served   []string
		rows     []string
		wantPath string
	}{
		{
			name:     "shop table goes to the shop",
			served:   []string{"/home/alice/public_html", "/home/alice/shop.example"},
			rows:     []string{"alice_wp\twp_shop_posts\t8192"},
			wantPath: shopCfg,
		},
		{
			name:     "main table goes to the main site",
			served:   []string{"/home/alice/public_html", "/home/alice/shop.example"},
			rows:     []string{"alice_wp\twp_posts\t8192"},
			wantPath: mainCfg,
		},
		{
			name:   "dormant shop keeps its tables",
			served: []string{"/home/alice/public_html"},
			rows:   []string{"alice_wp\twp_shop_posts\t8192"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withMyISAMHost(t, map[string]string{
				mainCfg: wpConfigFor("alice_wp", "localhost", "wp_"),
				shopCfg: wpConfigFor("alice_wp", "localhost", "wp_shop_"),
			}, tc.served...)
			withMyISAMTables(t, tc.rows...)

			findings := CheckWPMyISAM(context.Background(), &config.Config{}, nil)

			if tc.wantPath == "" {
				if len(findings) != 0 {
					t.Fatalf("findings = %+v, want none", findings)
				}
				return
			}
			if len(findings) != 1 || !strings.Contains(findings[0].Details, tc.wantPath) {
				t.Fatalf("findings = %+v, want one for %s", findings, tc.wantPath)
			}
		})
	}
}

// Installs that load no traffic, or whose database lives elsewhere, are not
// this server's performance problem. A schema with the same name on the local
// server is a different database, often a stale copy left by a migration.
func TestCheckWPMyISAM_SkipsInstallsThatCannotBeHurt(t *testing.T) {
	const cfgPath = "/home/alice/public_html/wp-config.php"
	for _, tc := range []struct {
		name      string
		dbHost    string
		served    bool
		suspended bool
	}{
		{name: "remote database", dbHost: "db.example.com", served: true},
		{name: "dormant root", dbHost: "localhost"},
		{name: "suspended account", dbHost: "localhost", served: true, suspended: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			served := []string{"/home/carol/public_html"}
			if tc.served {
				served = []string{"/home/alice/public_html"}
			}
			host := withMyISAMHost(t, map[string]string{cfgPath: wpConfigFor("alice_wp", tc.dbHost, "wp_")}, served...)
			host.suspended["alice"] = tc.suspended
			withMyISAMTables(t, "alice_wp\twp_posts\t8192")

			if findings := CheckWPMyISAM(context.Background(), &config.Config{}, nil); len(findings) != 0 {
				t.Fatalf("findings = %+v, want none", findings)
			}
		})
	}
}

// Two served document roots configured with the same database and prefix are
// one set of tables, reported once.
func TestCheckWPMyISAM_ReportsSharedTablesOnce(t *testing.T) {
	withMyISAMHost(t, map[string]string{
		"/home/alice/public_html/wp-config.php":   wpConfigFor("alice_wp", "localhost", "wp_"),
		"/home/alice/alias.example/wp-config.php": wpConfigFor("alice_wp", "localhost", "wp_"),
	}, "/home/alice/public_html", "/home/alice/alias.example")
	withMyISAMTables(t, "alice_wp\twp_posts\t8192")

	if findings := CheckWPMyISAM(context.Background(), &config.Config{}, nil); len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one", findings)
	}
}

// Table sizes change on every scan. A dismissed finding must stay dismissed
// while the same tables remain MyISAM.
func TestCheckWPMyISAM_IdentitySurvivesSizeChanges(t *testing.T) {
	withMyISAMHost(t, map[string]string{
		"/home/alice/public_html/wp-config.php": wpConfigFor("alice_wp", "localhost", "wp_"),
	}, "/home/alice/public_html")

	withMyISAMTables(t, "alice_wp\twp_posts\t8192")
	before := CheckWPMyISAM(context.Background(), &config.Config{}, nil)
	withMyISAMTables(t, "alice_wp\twp_posts\t52428800", "alice_wp\twp_options\t4096")
	after := CheckWPMyISAM(context.Background(), &config.Config{}, nil)

	if len(before) != 1 || len(after) != 1 {
		t.Fatalf("findings before/after = %d/%d, want 1/1", len(before), len(after))
	}
	if before[0].Details == after[0].Details {
		t.Fatal("fixture did not change the details")
	}
	if before[0].Key() != after[0].Key() {
		t.Errorf("identity changed with table sizes: %s -> %s", before[0].Key(), after[0].Key())
	}
}

// A failed scan must not read as "no MyISAM tables": the runner would retire
// every open finding.
func TestCheckWPMyISAM_CatalogueFailureMarksIncomplete(t *testing.T) {
	withMyISAMHost(t, map[string]string{
		"/home/alice/public_html/wp-config.php": wpConfigFor("alice_wp", "localhost", "wp_"),
	}, "/home/alice/public_html")
	mysqlclient.SetRootQueryForTest(func(context.Context, string, string, ...any) ([]string, error) {
		return nil, errors.New("database unavailable")
	})
	t.Cleanup(func() { mysqlclient.SetRootQueryForTest(nil) })

	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	findings := CheckWPMyISAM(ctx, &config.Config{}, nil)

	if len(findings) != 0 {
		t.Errorf("findings = %+v, want none", findings)
	}
	if !incomplete.contains("perf_wp_myisam") {
		t.Fatal("catalogue failure did not mark perf_wp_myisam incomplete")
	}
}

func TestCheckWPMyISAM_UnreadableConfigMarksIncompleteAndScansTheRest(t *testing.T) {
	const (
		aliceCfg = "/home/alice/public_html/wp-config.php"
		bobCfg   = "/home/bob/public_html/wp-config.php"
	)
	host := withMyISAMHost(t, map[string]string{
		aliceCfg: wpConfigFor("alice_wp", "localhost", "wp_"),
		bobCfg:   wpConfigFor("bob_wp", "localhost", "wp_"),
	}, "/home/alice/public_html", "/home/bob/public_html")
	host.unreadable[aliceCfg] = true
	withMyISAMTables(t, "alice_wp\twp_posts\t8192", "bob_wp\twp_posts\t8192")

	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	findings := CheckWPMyISAM(ctx, &config.Config{}, nil)

	if !incomplete.contains("perf_wp_myisam") {
		t.Error("unreadable wp-config.php did not mark perf_wp_myisam incomplete")
	}
	if len(findings) != 1 || !strings.Contains(findings[0].Details, bobCfg) {
		t.Fatalf("findings = %+v, want one for %s", findings, bobCfg)
	}
}

func TestCheckWPMyISAM_DisabledWithPerformanceMonitor(t *testing.T) {
	withMyISAMHost(t, map[string]string{
		"/home/alice/public_html/wp-config.php": wpConfigFor("alice_wp", "localhost", "wp_"),
	}, "/home/alice/public_html")
	calls := withMyISAMTables(t, "alice_wp\twp_posts\t8192")
	disabled := false
	cfg := &config.Config{}
	cfg.Performance.Enabled = &disabled

	if findings := CheckWPMyISAM(context.Background(), cfg, nil); len(findings) != 0 {
		t.Errorf("findings = %+v, want none", findings)
	}
	if *calls != 0 {
		t.Errorf("catalogue queried %d times with the performance monitor off", *calls)
	}
}

func TestWPDBHostIsLocal(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost":                           true,
		"LOCALHOST":                           true,
		"localhost:/var/lib/mysql/mysql.sock": true,
		"127.0.0.1":                           true,
		"127.0.0.1:3306":                      true,
		"::1":                                 true,
		"[::1]:3306":                          true,
		"db.example.com":                      false,
		"192.0.2.10":                          false,
		"192.0.2.10:3306":                     false,
		"localhost.example.com":               false,
		"2001:db8::10":                        false,
	} {
		if got := wpDBHostIsLocal(host); got != want {
			t.Errorf("wpDBHostIsLocal(%q) = %v, want %v", host, got, want)
		}
	}
}
