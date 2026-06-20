package checks

import (
	"context"
	"strings"
	"testing"
)

func TestVerifyDBRogueAdmin(t *testing.T) {
	details := "Database: alice_wp\nTable prefix: wp_\nUser ID: 5\nLogin: rogue\nEmail: x@tempmail.com\nRegistered: 2026-06-20"
	msg := "New WordPress admin account created in last 7 days: rogue (account: alice)"

	t.Run("resolved when account gone or demoted", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(schema, query string, args ...any) ([]string, error) {
			if schema != "alice_wp" || !strings.Contains(query, "`wp_users`") {
				t.Fatalf("schema=%q query=%s", schema, query)
			}
			return nil, nil
		})
		res := verifyDBRogueAdmin(msg, details)
		if !res.Checked || !res.Resolved {
			t.Errorf("want checked+resolved, got %+v", res)
		}
	})

	t.Run("unresolved when still admin", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) { return []string{"5"}, nil })
		res := verifyDBRogueAdmin(msg, details)
		if !res.Checked || res.Resolved {
			t.Errorf("want checked+unresolved, got %+v", res)
		}
	})

	t.Run("unresolved when legacy finding matches a later shared-database prefix", func(t *testing.T) {
		withMultiWPVerifyDiscovery(t, []wpVerifySite{
			{account: "alice", path: "/home/alice/public_html/wp-config.php", dbName: "alice_wp", prefix: "wp_"},
			{account: "alice", path: "/home/alice/shop/wp-config.php", dbName: "alice_wp", prefix: "shop_"},
		})
		var queried []string
		withRootQuery(t, func(_ string, _ string, args ...any) ([]string, error) {
			queried = append(queried, args[0].(string))
			if args[0] == "shop_capabilities" {
				return []string{"5"}, nil
			}
			return nil, nil
		})
		res := verifyDBRogueAdmin(msg, strings.ReplaceAll(details, "Table prefix: wp_\n", ""))
		if !res.Checked || res.Resolved {
			t.Errorf("want checked+unresolved, got %+v", res)
		}
		if strings.Join(queried, ",") != "wp_capabilities,shop_capabilities" {
			t.Errorf("queried prefixes = %v", queried)
		}
	})

	t.Run("not checked on query error", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) { return nil, context.DeadlineExceeded })
		res := verifyDBRogueAdmin(msg, details)
		if res.Checked {
			t.Errorf("query error must not be checked, got %+v", res)
		}
	})

	t.Run("not checked for non-numeric user id", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		res := verifyDBRogueAdmin(msg, "Database: alice_wp\nUser ID: 5; DROP")
		if res.Checked {
			t.Errorf("bad user id must not be checked, got %+v", res)
		}
	})
}

func TestVerifyDBSuspiciousAdminEmail(t *testing.T) {
	details := "Database: alice_wp\nTable prefix: wp_\nEmail: x@tempmail.com"
	msg := "WordPress admin 'rogue' has disposable email (account: alice)"

	t.Run("resolved when no admin uses the email", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) { return nil, nil })
		res := verifyDBSuspiciousAdminEmail(msg, details)
		if !res.Checked || !res.Resolved {
			t.Errorf("want checked+resolved, got %+v", res)
		}
	})

	t.Run("unresolved when an admin still uses the email", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) { return []string{"5"}, nil })
		res := verifyDBSuspiciousAdminEmail(msg, details)
		if !res.Checked || res.Resolved {
			t.Errorf("want checked+unresolved, got %+v", res)
		}
	})

	t.Run("honors the table prefix on new findings", func(t *testing.T) {
		withMultiWPVerifyDiscovery(t, []wpVerifySite{
			{account: "alice", path: "/home/alice/public_html/wp-config.php", dbName: "alice_wp", prefix: "wp_"},
			{account: "alice", path: "/home/alice/shop/wp-config.php", dbName: "alice_wp", prefix: "shop_"},
		})
		withRootQuery(t, func(_ string, _ string, args ...any) ([]string, error) {
			if args[0] != "shop_capabilities" {
				t.Fatalf("capability key = %v, want shop_capabilities", args[0])
			}
			return []string{"5"}, nil
		})
		res := verifyDBSuspiciousAdminEmail(
			"WordPress admin 'rogue' has disposable email (account: alice)",
			"Database: alice_wp\nTable prefix: shop_\nEmail: x@tempmail.com")
		if !res.Checked || res.Resolved {
			t.Errorf("want checked+unresolved, got %+v", res)
		}
	})
}

type cmsAdminCase struct {
	name    string
	verify  func(message, details string) VerifyResult
	message string
	details string
	schema  string
	table   string // substring the query must reference
}

func TestVerifyCMSAdminInjection(t *testing.T) {
	cases := []struct {
		setup func(t *testing.T)
		c     cmsAdminCase
	}{
		{
			setup: func(t *testing.T) { f, s := drupalFiles(); withCMSVerifyOS(t, f, s) },
			c: cmsAdminCase{
				name: "drupal", verify: verifyDrupalAdminInjection,
				message: "Drupal administrator account on bob: 42",
				details: "Account: bob\nRow: 42\tadmin\tx@y\nReview: confirm this is legit.",
				schema:  "drupal_db", table: "user__roles",
			},
		},
		{
			setup: func(t *testing.T) { withCMSVerifyOS(t, joomlaFiles(), nil) },
			c: cmsAdminCase{
				name: "joomla", verify: verifyJoomlaAdminInjection,
				message: "Joomla Super User account on bob: 7",
				details: "Account: bob\nRow: 7\tadmin\tx@y\nReview: confirm.",
				schema:  "joomla_db", table: "user_usergroup_map",
			},
		},
		{
			setup: func(t *testing.T) { withCMSVerifyOS(t, magentoFiles(), nil) },
			c: cmsAdminCase{
				name: "magento", verify: verifyMagentoAdminInjection,
				message: "Magento M2 admin account on bob: user_id=3",
				details: "Account: bob\nRow: 3\tadmin\tx@y\nReview: confirm.",
				schema:  "magento_db", table: "admin_user",
			},
		},
		{
			setup: func(t *testing.T) { withCMSVerifyOS(t, opencartFiles(), nil) },
			c: cmsAdminCase{
				name: "opencart", verify: verifyOpenCartAdminInjection,
				message: "OpenCart admin account on bob: user_id=9",
				details: "Account: bob\nRow: 9\tadmin\tx@y\nReview: confirm.",
				schema:  "oc_db", table: "user",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.c.name+"/resolved", func(t *testing.T) {
			tc.setup(t)
			withRootQuery(t, func(schema, query string, _ ...any) ([]string, error) {
				if schema != tc.c.schema {
					t.Errorf("schema=%q want %q", schema, tc.c.schema)
				}
				if !strings.Contains(query, tc.c.table) {
					t.Errorf("query %s does not reference %s", query, tc.c.table)
				}
				return nil, nil
			})
			res := tc.c.verify(tc.c.message, tc.c.details)
			if !res.Checked || !res.Resolved {
				t.Errorf("want checked+resolved, got %+v", res)
			}
		})
		t.Run(tc.c.name+"/unresolved", func(t *testing.T) {
			tc.setup(t)
			withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) { return []string{"1"}, nil })
			res := tc.c.verify(tc.c.message, tc.c.details)
			if !res.Checked || res.Resolved {
				t.Errorf("want checked+unresolved, got %+v", res)
			}
		})
		t.Run(tc.c.name+"/query-error", func(t *testing.T) {
			tc.setup(t)
			withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) { return nil, context.DeadlineExceeded })
			res := tc.c.verify(tc.c.message, tc.c.details)
			if res.Checked {
				t.Errorf("query error must not be checked, got %+v", res)
			}
		})
	}
}
