package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/mysqlclient"
)

func TestVerifyDBObjectUnexpected(t *testing.T) {
	details := "Account: bob\nSchema: bob_db\nKind: trigger\nName: evil_trg\nBody: BEGIN ... END"
	msg := "Unexpected trigger evil_trg in bob.bob_db"

	t.Run("resolved when object gone", func(t *testing.T) {
		withRootQuery(t, func(_, query string, _ ...any) ([]string, error) {
			if !strings.Contains(query, "INFORMATION_SCHEMA.TRIGGERS") {
				t.Fatalf("wrong query: %s", query)
			}
			return nil, nil
		})
		res := verifyDBObject(msg, details, false)
		if !res.Checked || !res.Resolved {
			t.Errorf("want checked+resolved, got %+v", res)
		}
	})

	t.Run("unresolved when object still present", func(t *testing.T) {
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) {
			return []string{"BEGIN harmless END"}, nil
		})
		res := verifyDBObject(msg, details, false)
		if !res.Checked || res.Resolved {
			t.Errorf("unexpected presence stays active, got %+v", res)
		}
	})

	t.Run("not checked on query error", func(t *testing.T) {
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) {
			return nil, context.DeadlineExceeded
		})
		res := verifyDBObject(msg, details, false)
		if res.Checked {
			t.Errorf("query error must not be checked, got %+v", res)
		}
	})
}

func TestVerifyDBObjectMalicious(t *testing.T) {
	details := "Account: bob\nSchema: bob_db\nKind: function\nName: x_fn\nBody: ..."
	msg := "Malicious function x_fn in bob.bob_db"

	t.Run("resolved when gone", func(t *testing.T) {
		withRootQuery(t, func(_, query string, _ ...any) ([]string, error) {
			if !strings.Contains(query, "INFORMATION_SCHEMA.ROUTINES") {
				t.Fatalf("wrong query: %s", query)
			}
			return nil, nil
		})
		res := verifyDBObject(msg, details, true)
		if !res.Checked || !res.Resolved {
			t.Errorf("want checked+resolved, got %+v", res)
		}
	})

	t.Run("resolved when body cleaned", func(t *testing.T) {
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) {
			return []string{"BEGIN RETURN 1 END"}, nil
		})
		res := verifyDBObject(msg, details, true)
		if !res.Checked || !res.Resolved {
			t.Errorf("clean body resolves, got %+v", res)
		}
	})

	t.Run("unresolved when body still malicious", func(t *testing.T) {
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) {
			return []string{"BEGIN SELECT base64_decode(x) INTO OUTFILE '/tmp/x' END"}, nil
		})
		res := verifyDBObject(msg, details, true)
		if !res.Checked || res.Resolved {
			t.Errorf("malicious body stays active, got %+v", res)
		}
	})
}

func TestVerifyDBObjectRejectsBadKind(t *testing.T) {
	res := verifyDBObject("x", "Account: bob\nSchema: bob_db\nKind: tabl\nName: foo", true)
	if res.Checked {
		t.Errorf("bad kind must not be checked, got %+v", res)
	}
}

func TestVerifyDBMagicTokenUser(t *testing.T) {
	details := "Account: alice\nSchema: alice_wp\nTable prefix: wp_\nToken: Ab1cdefghij\nUser ID: 5\nUser login: x"
	msg := "User x (ID 5) carries backdoor activation token in alice.wp_users"

	t.Run("resolved when flagged user no longer carries token", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(schema, query string, args ...any) ([]string, error) {
			requireMagicTokenUserQuery(t, schema, query, "`wp_users`", args...)
			return nil, nil
		})
		res := verifyDBMagicTokenUser(msg, details)
		if !res.Checked || !res.Resolved {
			t.Errorf("want checked+resolved, got %+v", res)
		}
	})

	t.Run("unresolved when flagged user still carries token", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(schema, query string, args ...any) ([]string, error) {
			requireMagicTokenUserQuery(t, schema, query, "`wp_users`", args...)
			return []string{"5"}, nil
		})
		res := verifyDBMagicTokenUser(msg, details)
		if !res.Checked || res.Resolved {
			t.Errorf("want checked+unresolved, got %+v", res)
		}
	})

	t.Run("uses legacy message prefix when details lack it", func(t *testing.T) {
		legacyDetails := "Account: alice\nSchema: alice_wp\nToken: Ab1cdefghij\nUser ID: 5\nUser login: x"
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(schema, query string, args ...any) ([]string, error) {
			requireMagicTokenUserQuery(t, schema, query, "`wp_users`", args...)
			return nil, nil
		})
		res := verifyDBMagicTokenUser(msg, legacyDetails)
		if !res.Checked || !res.Resolved {
			t.Errorf("want checked+resolved from legacy message prefix, got %+v", res)
		}
	})

	t.Run("does not query a different current prefix", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_new_")
		mysqlclient.SetRootQueryForTest(func(_ context.Context, _, _ string, _ ...any) ([]string, error) {
			t.Fatal("must not query a table other than the finding table")
			return nil, nil
		})
		t.Cleanup(func() { mysqlclient.SetRootQueryForTest(nil) })
		res := verifyDBMagicTokenUser(msg, details)
		if res.Checked {
			t.Errorf("changed prefix must not be checked, got %+v", res)
		}
	})

	t.Run("not checked for invalid user id", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		mysqlclient.SetRootQueryForTest(func(_ context.Context, _, _ string, _ ...any) ([]string, error) {
			t.Fatal("must not query for invalid user id")
			return nil, nil
		})
		t.Cleanup(func() { mysqlclient.SetRootQueryForTest(nil) })
		res := verifyDBMagicTokenUser(msg, "Account: alice\nSchema: alice_wp\nTable prefix: wp_\nToken: Ab1cdefghij\nUser ID: 5 OR 1=1")
		if res.Checked {
			t.Errorf("invalid user id must not be checked, got %+v", res)
		}
	})

	t.Run("not checked for invalid token", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		mysqlclient.SetRootQueryForTest(func(_ context.Context, _, _ string, _ ...any) ([]string, error) {
			t.Fatal("must not query for invalid token")
			return nil, nil
		})
		t.Cleanup(func() { mysqlclient.SetRootQueryForTest(nil) })
		res := verifyDBMagicTokenUser(msg, "Account: alice\nSchema: alice_wp\nTable prefix: wp_\nToken: short\nUser ID: 5")
		if res.Checked {
			t.Errorf("invalid token must not be checked, got %+v", res)
		}
	})
}

func requireMagicTokenUserQuery(t *testing.T, schema, query, table string, args ...any) {
	t.Helper()
	if schema != "alice_wp" || !strings.Contains(query, table) {
		t.Fatalf("schema=%q query=%s", schema, query)
	}
	if !strings.Contains(query, "ID = ?") || !strings.Contains(query, "display_name LIKE ?") {
		t.Fatalf("query must target the flagged user and token: %s", query)
	}
	if len(args) != 2 || args[0] != "5" || args[1] != "%Ab1cdefghij%" {
		t.Fatalf("args = %#v, want user ID and token LIKE pattern", args)
	}
}
