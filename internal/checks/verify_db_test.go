package checks

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/mysqlclient"
)

// wpVerifyOS stubs osFS so the WordPress DB re-checks can re-discover an
// account's wp-config.php (DB name + table prefix) without a real filesystem.
type wpVerifyOS struct {
	mockOS
	t         *testing.T
	account   string
	dbName    string
	prefix    string
	multisite bool
}

func (m *wpVerifyOS) Glob(pattern string) ([]string, error) {
	if strings.Contains(pattern, "/home/"+m.account+"/") {
		return []string{"/home/" + m.account + "/public_html/wp-config.php"}, nil
	}
	return nil, nil
}

func (m *wpVerifyOS) Open(name string) (*os.File, error) {
	if name != "/home/"+m.account+"/public_html/wp-config.php" {
		return nil, os.ErrNotExist
	}
	prefix := m.prefix
	if prefix == "" {
		prefix = "wp_"
	}
	body := fmt.Sprintf(
		"define('DB_NAME','%s');\ndefine('DB_USER','u');\ndefine('DB_PASSWORD','p');\n$table_prefix = '%s';\n",
		m.dbName, prefix)
	if m.multisite {
		body += "define('MULTISITE', true);\n"
	}
	tmp, err := os.CreateTemp(m.t.TempDir(), "wpcfg*.php")
	if err != nil {
		return nil, err
	}
	if _, err := tmp.WriteString(body); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if _, err := tmp.Seek(0, 0); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	return tmp, nil
}

// withWPVerifyDiscovery points osFS at a wpVerifyOS for one account/db/prefix.
func withWPVerifyDiscovery(t *testing.T, account, dbName, prefix string) {
	t.Helper()
	old := osFS
	osFS = &wpVerifyOS{t: t, account: account, dbName: dbName, prefix: prefix}
	t.Cleanup(func() { osFS = old })
}

func withWPVerifyMultisiteDiscovery(t *testing.T, account, dbName, prefix string) {
	t.Helper()
	old := osFS
	osFS = &wpVerifyOS{t: t, account: account, dbName: dbName, prefix: prefix, multisite: true}
	t.Cleanup(func() { osFS = old })
}

// withRootQuery installs a root-MySQL stub returning the supplied rows/err for
// every query and clears it on cleanup.
func withRootQuery(t *testing.T, fn func(schema, query string, args ...any) ([]string, error)) {
	t.Helper()
	mysqlclient.SetRootQueryForTest(func(_ context.Context, schema, query string, args ...any) ([]string, error) {
		return fn(schema, query, args...)
	})
	t.Cleanup(func() { mysqlclient.SetRootQueryForTest(nil) })
}

func TestDetailField(t *testing.T) {
	details := "Database: alice_wp\nOption: siteurl\nContent preview: x"
	if got := detailField(details, "Database"); got != "alice_wp" {
		t.Errorf("Database = %q, want alice_wp", got)
	}
	if got := detailField(details, "Option"); got != "siteurl" {
		t.Errorf("Option = %q, want siteurl", got)
	}
	if got := detailField(details, "Missing"); got != "" {
		t.Errorf("Missing = %q, want empty", got)
	}
}

func TestDBFindingAccount(t *testing.T) {
	// CMS findings carry Account in details.
	if got := dbFindingAccount("anything", "Account: bob\nConfig name: x"); got != "bob" {
		t.Errorf("account from details = %q, want bob", got)
	}
	// WP content findings carry it only in the message.
	if got := dbFindingAccount("Malicious script injection in wp_options 'x' (account: alice)", ""); got != "alice" {
		t.Errorf("account from message = %q, want alice", got)
	}
}

func TestVerifyDBSiteurlHijack(t *testing.T) {
	details := "Database: alice_wp\nsiteurl = http://evil/<script>"
	msg := "WordPress siteurl contains malicious code (account: alice)"

	t.Run("resolved when option cleaned", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(schema, query string, args ...any) ([]string, error) {
			if schema != "alice_wp" {
				t.Errorf("schema = %q, want alice_wp", schema)
			}
			return []string{"http://legit.example/"}, nil
		})
		res := verifyDBSiteurlHijack(msg, details)
		if !res.Checked || !res.Resolved {
			t.Errorf("want checked+resolved, got %+v", res)
		}
	})

	t.Run("resolved when option gone", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) { return nil, nil })
		res := verifyDBSiteurlHijack(msg, details)
		if !res.Checked || !res.Resolved {
			t.Errorf("want checked+resolved, got %+v", res)
		}
	})

	t.Run("unresolved when still malicious", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) {
			return []string{"http://evil/<script>x</script>"}, nil
		})
		res := verifyDBSiteurlHijack(msg, details)
		if !res.Checked || res.Resolved {
			t.Errorf("want checked+unresolved, got %+v", res)
		}
	})

	t.Run("unresolved when any matching row is still malicious", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) {
			return []string{"http://legit.example/", "http://evil/<script>x</script>"}, nil
		})
		res := verifyDBSiteurlHijack(msg, details)
		if !res.Checked || res.Resolved {
			t.Errorf("want checked+unresolved, got %+v", res)
		}
	})

	t.Run("not checked when query fails", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) {
			return nil, fmt.Errorf("connection refused")
		})
		res := verifyDBSiteurlHijack(msg, details)
		if res.Checked {
			t.Errorf("query failure must not be checked, got %+v", res)
		}
	})

	t.Run("not checked when site not discoverable", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "other_db", "wp_") // dbName mismatch
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) {
			t.Fatal("query must not run without discovery")
			return nil, nil
		})
		res := verifyDBSiteurlHijack(msg, details)
		if res.Checked {
			t.Errorf("missing discovery must not be checked, got %+v", res)
		}
	})
}

func TestVerifyDBOptionsInjection(t *testing.T) {
	t.Run("resolved when script url gone", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) {
			return []string{"a:1:{s:4:\"safe\";}"}, nil
		})
		res := verifyDBOptionsInjection(
			"Malicious script injection in wp_options 'widget_x' (account: alice)",
			"Database: alice_wp\nOption: widget_x\nMalicious URL: http://evil")
		if !res.Checked || !res.Resolved {
			t.Errorf("want checked+resolved, got %+v", res)
		}
	})

	t.Run("unresolved when external script url remains", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) {
			return []string{"<script src=http://evil.example/x.js></script>"}, nil
		})
		res := verifyDBOptionsInjection(
			"Malicious script injection in wp_options 'widget_x' (account: alice)",
			"Database: alice_wp\nOption: widget_x")
		if !res.Checked || res.Resolved {
			t.Errorf("want checked+unresolved, got %+v", res)
		}
	})

	t.Run("unresolved when core option holds script", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) {
			return []string{"My Blog <script>x</script>"}, nil
		})
		res := verifyDBOptionsInjection(
			"Malicious content in core wp_option 'blogname' (account: alice)",
			"Database: alice_wp\nOption: blogname")
		if !res.Checked || res.Resolved {
			t.Errorf("want checked+unresolved, got %+v", res)
		}
	})

	t.Run("unresolved when any matching row still has external script", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) {
			return []string{"safe", `<script src="http://evil.top/x.js"></script>`}, nil
		})
		res := verifyDBOptionsInjection(
			"Malicious script injection in wp_options 'widget_x' (account: alice)",
			"Database: alice_wp\nOption: widget_x")
		if !res.Checked || res.Resolved {
			t.Errorf("want checked+unresolved, got %+v", res)
		}
	})

	t.Run("uses table prefix detail", func(t *testing.T) {
		withWPVerifyMultisiteDiscovery(t, "alice", "alice_wp", "wp_")
		queriedExactPrefix := false
		withRootQuery(t, func(_, query string, _ ...any) ([]string, error) {
			if strings.Contains(query, "`wp_blogs`") {
				t.Fatal("exact table prefix should not require multisite enumeration")
			}
			if strings.Contains(query, "`wp_2_options`") {
				queriedExactPrefix = true
				return []string{`<script src="http://evil.top/x.js"></script>`}, nil
			}
			if strings.Contains(query, "`wp_options`") {
				t.Fatalf("queried base prefix instead of exact prefix: %s", query)
			}
			return nil, nil
		})
		res := verifyDBOptionsInjection(
			"Malicious script injection in wp_options 'widget_x' (account: alice)",
			"Database: alice_wp\nTable prefix: wp_2_\nOption: widget_x")
		if !queriedExactPrefix {
			t.Fatal("exact table prefix was not queried")
		}
		if !res.Checked || res.Resolved {
			t.Errorf("want checked+unresolved, got %+v", res)
		}
	})

	t.Run("rejects invalid account before filesystem and query", func(t *testing.T) {
		withWPVerifyDiscovery(t, "..", "alice_wp", "wp_")
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) {
			t.Fatal("query must not run for invalid account")
			return nil, nil
		})
		res := verifyDBOptionsInjection(
			"Malicious script injection in wp_options 'widget_x' (account: ..)",
			"Database: alice_wp\nOption: widget_x")
		if res.Checked {
			t.Errorf("invalid account must not be checked, got %+v", res)
		}
	})
}

func TestVerifyDBPostInjection(t *testing.T) {
	details := "Database: alice_wp\nAffected post IDs: 12, 34\nPattern: base64_decode"
	msg := "WordPress posts contain base64_decode in database content (account: alice, 2 posts)"

	t.Run("resolved when posts cleaned", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) {
			return []string{"12\tclean body\t", "34\talso clean\t"}, nil
		})
		res := verifyDBPostInjection(msg, details)
		if !res.Checked || !res.Resolved {
			t.Errorf("want checked+resolved, got %+v", res)
		}
	})

	t.Run("unresolved when a post still injected", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(_, query string, _ ...any) ([]string, error) {
			if !strings.Contains(query, "post_status='publish'") || !strings.Contains(query, "post_type NOT IN") {
				t.Fatalf("post verifier query does not mirror detector filters: %s", query)
			}
			return []string{"12\tclean\t", "34\tbad base64_decode($x)\t"}, nil
		})
		res := verifyDBPostInjection(msg, details)
		if !res.Checked || res.Resolved {
			t.Errorf("want checked+unresolved, got %+v", res)
		}
	})

	t.Run("not checked when pattern unknown", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		res := verifyDBPostInjection(msg, "Database: alice_wp\nAffected post IDs: 12\nPattern: not_a_real_pattern")
		if res.Checked {
			t.Errorf("unknown pattern must not be checked, got %+v", res)
		}
	})

	t.Run("fallback checks multisite secondary prefixes", func(t *testing.T) {
		withWPVerifyMultisiteDiscovery(t, "alice", "alice_wp", "wp_")
		queriedSecondary := false
		withRootQuery(t, func(_, query string, _ ...any) ([]string, error) {
			switch {
			case strings.Contains(query, "`wp_blogs`"):
				return []string{"2"}, nil
			case strings.Contains(query, "`wp_2_posts`"):
				queriedSecondary = true
				return []string{"34\tbad base64_decode($x)\t"}, nil
			case strings.Contains(query, "`wp_posts`"):
				return nil, nil
			default:
				return nil, nil
			}
		})
		res := verifyDBPostInjection(msg, details)
		if !queriedSecondary {
			t.Fatal("secondary multisite prefix was not queried")
		}
		if !res.Checked || res.Resolved {
			t.Errorf("want checked+unresolved, got %+v", res)
		}
	})
}

func TestVerifyDBSpamInjection(t *testing.T) {
	details := "Database: alice_wp"
	msg := "WordPress posts contain cloaked spam keyword 'viagra' (3 posts, account: alice)"

	t.Run("resolved when no spam remains", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) { return nil, nil })
		res := verifyDBSpamInjection(msg, details)
		if !res.Checked || !res.Resolved {
			t.Errorf("want checked+resolved, got %+v", res)
		}
	})

	t.Run("unresolved when spam still present", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) {
			return []string{"5\t<div style=\"position:absolute;left:-9999px\"><a href=http://x/buy-viagra>viagra</a></div>"}, nil
		})
		res := verifyDBSpamInjection(msg, details)
		if !res.Checked || res.Resolved {
			t.Errorf("want checked+unresolved, got %+v", res)
		}
	})
}
