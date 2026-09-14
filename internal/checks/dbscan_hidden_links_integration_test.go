//go:build mysqlintegration

package checks

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Run against disposable MySQL 8 or MariaDB with CSM_TEST_MYSQL_SOCKET set. Go's RE2
// matcher cannot reproduce ICU's regex execution limit or SQL escape modes.
func hiddenLinkMySQLConn(t *testing.T) (*sql.Conn, context.Context) {
	t.Helper()
	socket := os.Getenv("CSM_TEST_MYSQL_SOCKET")
	if socket == "" {
		t.Fatal("CSM_TEST_MYSQL_SOCKET is required")
	}
	cfg := mysql.NewConfig()
	cfg.User, cfg.Net, cfg.Addr, cfg.DBName = "root", "unix", socket, "mysql"
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	var version string
	if err := conn.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(version, "MariaDB") {
		var regexLimit int
		if err := conn.QueryRowContext(ctx, "SELECT @@GLOBAL.regexp_time_limit").Scan(&regexLimit); err != nil {
			t.Fatal(err)
		}
		if regexLimit != 32 {
			t.Fatalf("start disposable MySQL with regexp_time_limit=32; got %d", regexLimit)
		}
	}
	if _, err := conn.ExecContext(ctx, "CREATE TEMPORARY TABLE csm_hidden_candidate (markup longtext) CHARACTER SET utf8mb4"); err != nil {
		t.Fatal(err)
	}
	return conn, ctx
}

func hiddenLinkMySQLCandidate(t *testing.T, conn *sql.Conn, ctx context.Context, markup string) int {
	t.Helper()
	if _, err := conn.ExecContext(ctx, "DELETE FROM csm_hidden_candidate"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, "INSERT INTO csm_hidden_candidate VALUES (?)", markup); err != nil {
		t.Fatal(err)
	}
	var got int
	if err := conn.QueryRowContext(ctx, "SELECT "+hiddenLinkCandidateCondition("markup")+" FROM csm_hidden_candidate").Scan(&got); err != nil {
		t.Fatalf("candidate selection failed: %v", err)
	}
	return got
}

func TestHiddenLinkPostRowsMySQLKeepsLateInjection(t *testing.T) {
	conn, ctx := hiddenLinkMySQLConn(t)
	if _, err := conn.ExecContext(ctx, "CREATE TEMPORARY TABLE csm_hidden_posts (ID bigint PRIMARY KEY, post_content longtext, post_status varchar(20), post_type varchar(20)) CHARACTER SET utf8mb4"); err != nil {
		t.Fatal(err)
	}
	previous := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		rows, err := conn.QueryContext(ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		var out []string
		escape := strings.NewReplacer("\\", "\\\\", "\t", "\\t", "\n", "\\n", "\r", "\\r", "\x00", "\\0")
		for rows.Next() {
			var id, head, tail, kind string
			var size int
			if err := rows.Scan(&id, &head, &tail, &size, &kind); err != nil {
				t.Fatal(err)
			}
			out = append(out, fmt.Sprintf("%s\t%s\t%s\t%d\t%s", id, escape.Replace(head), escape.Replace(tail), size, kind))
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	t.Cleanup(func() { runMySQLQuery = previous })
	for _, markup := range []string{
		strings.Repeat(`<div style="color:black">ordinary text</div>`, 1600),
		`<div style="display:block">visible</div>`,
		`<div style="left:0">the left side - ordinary layout</div>`,
		`<div style="display:/*theme*/block;left:/*layout*/0">visible</div>`,
		`<div style="color:black">price &#36;10</div>`,
		`<div style="color:black">path\name</div>`,
		`{"style":"color:black","label":"&#32;"}`,
	} {
		if _, err := conn.ExecContext(ctx, "DELETE FROM csm_hidden_posts"); err != nil {
			t.Fatal(err)
		}
		for id := 1; id <= 250; id++ {
			if _, err := conn.ExecContext(ctx, "INSERT INTO csm_hidden_posts VALUES (?, ?, 'publish', 'post')", id, markup); err != nil {
				t.Fatal(err)
			}
		}
		injected := strings.Repeat("padding ", 9000) + `<div style="left:&#45;9999px"><a href="https://spam.example/">x</a></div>`
		if _, err := conn.ExecContext(ctx, "INSERT INTO csm_hidden_posts VALUES (251, ?, 'publish', 'post'), (252, ?, 'draft', 'post'), (253, ?, 'publish', 'revision')", injected, injected, injected); err != nil {
			t.Fatal(err)
		}
		scanCtx, incomplete := withIncompleteCheckCollector(ctx)
		rows := hiddenLinkPostRows(wpDBCreds{queryCtx: scanCtx}, "csm_hidden_")
		if len(rows) != 1 || rows[0].label != "251" {
			t.Fatalf("benign content exhausted candidates or row exclusions failed: got %d rows", len(rows))
		}
		if incomplete.contains("db_content") {
			t.Fatal("benign rows exhausted the candidate limit")
		}
		if hit := hiddenOffsiteLinkSamples(rows[0], []string{"shop.example"}); !hit.offScreen || len(hit.hosts) != 1 {
			t.Fatalf("late encoded injection was not detected: %+v", hit)
		}
	}
}

func TestHiddenLinkCandidateMySQL(t *testing.T) {
	conn, ctx := hiddenLinkMySQLConn(t)
	for _, mode := range []string{"", "NO_BACKSLASH_ESCAPES"} {
		t.Run("sql_mode="+mode, func(t *testing.T) {
			if _, err := conn.ExecContext(ctx, "SET SESSION sql_mode = ?", mode); err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				name, markup string
				want         int
			}{
				{"ordinary text", strings.Repeat("ordinary text ", 10000), 0},
				{"repeated style text", strings.Repeat("style=color:black;", 4096), 0},
				{"ordinary HTML", strings.Repeat("<div style=color:black>ordinary text</div>", 1600), 0},
				{"visible declarations", strings.Repeat("<div style=display:block>visible</div>", 1600), 0},
				{"entities outside styles", strings.Repeat("<div style=color:black>text&#32;</div>", 1600), 0},
				{"backslashes outside styles", strings.Repeat(`<div style=color:black>path\name</div>`, 1600), 0},
				{"style text before entity", strings.Repeat("style=color:black;", 4096) + ">text&#32;", 0},
				{"serialized style metadata", `{"style":"color:black","label":"&#32;"}`, 0},
				{"CSS comments", "display" + strings.Repeat("/**/", 4096) + "block", 0},
				{"offscreen", `<div style="left:-9999px">`, 1},
				{"commented hiding", `<div style="display:/* theme fallback */none">`, 1},
				{"calc", `<div style="left:calc(-9999px)">`, 1},
				{"opacity", `<div style="opacity:-.1">`, 1},
				{"HTML entity", `<div style="d&#105;splay:none">`, 1},
				{"named entity", `<div style="display&colon;none">`, 1},
				{"CSS escape", `<div style="d\69splay:none">`, 1},
				{"encoded trailing injection", strings.Repeat("<div style=color:black>text&#32;</div>", 1600) + `<div style="d&#105;splay:none">`, 1},
				{"trailing injection", strings.Repeat("<div style=color:black>text</div>", 1600) + `<div style="left:-9999px">`, 1},
			} {
				t.Run(tc.name, func(t *testing.T) {
					got := hiddenLinkMySQLCandidate(t, conn, ctx, tc.markup)
					if got != tc.want {
						t.Fatalf("candidate = %d, want %d", got, tc.want)
					}
				})
			}
		})
	}
}

// Exercise the emitted SQL, not Go RE2, for every previously covered style.
func TestHiddenLinkCandidatePatternCoversParsedStyles(t *testing.T) {
	conn, ctx := hiddenLinkMySQLConn(t)
	candidate := func(markup string) bool {
		t.Helper()
		return hiddenLinkMySQLCandidate(t, conn, ctx, markup) == 1
	}
	for _, style := range []string{
		"display:none",
		"display:/**/none",
		"display:/* theme fallback */none",
		"visibility: hidden!important",
		"opacity:0.0",
		"opacity:.0",
		"opacity:-.0",
		"opacity:-0.1",
		"opacity:-10%",
		"opacity:-1e400",
		"opacity:.00",
		"left:-100em",
		"left:calc(-9999px)",
		"MARGIN-LEFT: -9999PX",
	} {
		t.Run(style, func(t *testing.T) {
			if !candidate(`<div style="` + style + `">`) {
				t.Fatalf("candidate query misses supported style %q", style)
			}
		})
	}
	for _, markup := range []string{
		`<div style="display&#58;none">`,
		`<div style="d&#105;splay:none">`,
		`<div style="display:n&#111;ne">`,
	} {
		if !candidate(markup) {
			t.Errorf("candidate query misses encoded style %q", markup)
		}
	}
}

func TestHiddenLinkCandidateMySQLParserWhitespace(t *testing.T) {
	conn, ctx := hiddenLinkMySQLConn(t)
	for _, space := range []string{" ", "\t", "\r\n", "\f", "\u00a0", "\u2009", "\u3000"} {
		t.Run(fmt.Sprintf("%x", space), func(t *testing.T) {
			markup := `<div style="opacity:` + space + `0"><a href="https://spam.example/">x</a></div>`
			if hit := hiddenOffsiteLinks(markup, "shop.example"); len(hit.hosts) != 1 {
				t.Fatal("fixture is not recognized by the existing CSS parser")
			}
			if got := hiddenLinkMySQLCandidate(t, conn, ctx, markup); got != 1 {
				t.Fatal("SQL selection discarded a style recognized by the CSS parser")
			}
		})
	}
}

func TestHiddenLinkCandidateMySQLLegacyCharset(t *testing.T) {
	conn, ctx := hiddenLinkMySQLConn(t)
	if _, err := conn.ExecContext(ctx, "ALTER TABLE csm_hidden_candidate CONVERT TO CHARACTER SET latin1"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		markup string
		want   int
	}{
		{`<div style="color:black">ordinary</div>`, 0},
		{`<div style="display:none">`, 1},
		{`<div style="left:&#45;9999px">`, 1},
	} {
		if got := hiddenLinkMySQLCandidate(t, conn, ctx, tc.markup); got != tc.want {
			t.Fatalf("latin1 candidate = %d, want %d", got, tc.want)
		}
	}
}
