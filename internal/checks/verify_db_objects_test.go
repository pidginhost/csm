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
	details := "Account: alice\nSchema: alice_wp\nToken: Ab1cdefghij\nUser ID: 5\nUser login: x"
	msg := "User x (ID 5) carries backdoor activation token in alice.wp_users"

	t.Run("resolved when no user carries token", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(schema, query string, _ ...any) ([]string, error) {
			if schema != "alice_wp" || !strings.Contains(query, "`wp_users`") {
				t.Fatalf("schema=%q query=%s", schema, query)
			}
			return nil, nil
		})
		res := verifyDBMagicTokenUser(msg, details)
		if !res.Checked || !res.Resolved {
			t.Errorf("want checked+resolved, got %+v", res)
		}
	})

	t.Run("unresolved when a user still carries token", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) {
			return []string{"5"}, nil
		})
		res := verifyDBMagicTokenUser(msg, details)
		if !res.Checked || res.Resolved {
			t.Errorf("want checked+unresolved, got %+v", res)
		}
	})

	t.Run("not checked for invalid token", func(t *testing.T) {
		withWPVerifyDiscovery(t, "alice", "alice_wp", "wp_")
		mysqlclient.SetRootQueryForTest(func(_ context.Context, _, _ string, _ ...any) ([]string, error) {
			t.Fatal("must not query for invalid token")
			return nil, nil
		})
		t.Cleanup(func() { mysqlclient.SetRootQueryForTest(nil) })
		res := verifyDBMagicTokenUser(msg, "Account: alice\nSchema: alice_wp\nToken: short")
		if res.Checked {
			t.Errorf("invalid token must not be checked, got %+v", res)
		}
	})
}
