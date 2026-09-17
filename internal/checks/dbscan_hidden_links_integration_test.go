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

	"github.com/pidginhost/csm/internal/mysqlclient"
)

// Run against disposable MySQL 8 or MariaDB with CSM_TEST_MYSQL_SOCKET set. Go's RE2
// matcher cannot reproduce ICU's regex execution limit or SQL escape modes.
func hiddenLinkMySQLConn(t testing.TB) (*sql.Conn, context.Context) {
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
	if err := conn.QueryRowContext(ctx, "SELECT "+hiddenLinkCandidateCondition("markup", true)+" FROM csm_hidden_candidate").Scan(&got); err != nil {
		t.Fatalf("candidate selection failed: %v", err)
	}
	return got
}

// hiddenLinkMySQLArticle is ordinary block-editor markup: prose, inline styles,
// entities and escaped block attributes, with no hidden declaration.
func hiddenLinkMySQLArticle(bytes int) string {
	block := `<!-- wp:paragraph {"className":"is-style-lead \u0022x\u0022"} -->` +
		`<p class="has-text-color" style="color:#333;margin-top:10px;padding:0 1em">` +
		`Then the engineer went over the green lane and entered the garden near the entrance&#8217;s gate &amp; fence.</p>` +
		"<!-- /wp:paragraph -->\n"
	return strings.Repeat(block, bytes/len(block)+1)[:bytes]
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
		`<div style="display:/*theme*/block;left:/*layout*/0">none - visible</div>`,
		`<div style="display:/*theme*/block;color:black">none</div>`,
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
				{"repeated entities in text", `<div style="color:black">` + strings.Repeat("text&#32;", 4096) + "</div>", 0},
				{"repeated backslashes in text", `<div style="color:black">` + strings.Repeat(`path\name`, 4096) + "</div>", 0},
				{"repeated named entities in text", `<div style="color:black">` + strings.Repeat("text&colon;", 4096) + "</div>", 0},
				{"encoded attribute before style", `<div title="` + strings.Repeat("&#32;", 4096) + `" style="color:black">`, 0},
				{"serialized style metadata", `{"style":"color:black","label":"&#32;"}`, 0},
				{"CSS comments", "display" + strings.Repeat("/**/", 4096) + "block", 0},
				{"commented visible display with text", `<div style="display:/*theme*/block;color:black">none</div>`, 0},
				{"commented visible offset with text", `<div style="left:/*layout*/0">left - ordinary layout</div>`, 0},
				{"commented visible opacity", `<div style="opacity:/*theme*/1;left:0">visible</div>`, 0},
				{"repeated visible comments", strings.Repeat(`<div style="display:/*theme*/block">none</div>`, 1600), 0},
				{"long comment before hidden value", `<div style="display:/*` + strings.Repeat("theme ", 4096) + `*/none">`, 1},
				{"many comments before hidden value", `<div style="display:` + strings.Repeat("/**/", 4096) + `none">`, 1},
				{"long gaps around comment", `<div style="display:` + strings.Repeat(" ", 4096) + "/**/" + strings.Repeat(" ", 4096) + `none">`, 1},
				{"encoded style with many markers", `<div style="--label:` + strings.Repeat("&#32;", 4096) + `;d&#105;splay:none">`, 1},
				{"encoded style with intervening ampersand", `<div style="--label:a&b;d&#105;splay:none">`, 1},
				{"offscreen", `<div style="left:-9999px">`, 1},
				{"commented hiding", `<div style="display:/* theme fallback */none">`, 1},
				{"calc", `<div style="left:calc(-9999px)">`, 1},
				{"opacity", `<div style="opacity:-.1">`, 1},
				{"HTML entity", `<div style="d&#105;splay:none">`, 1},
				{"named entity", `<div style="display&colon;none">`, 1},
				{"CSS escape", `<div style="d\69splay:none">`, 1},
				{"encoded trailing injection", strings.Repeat("<div style=color:black>text&#32;</div>", 1600) + `<div style="d&#105;splay:none">`, 1},
				{"trailing injection", strings.Repeat("<div style=color:black>text</div>", 1600) + `<div style="left:-9999px">`, 1},
				{"large article with stylesheet comment", "<style>/* theme */</style>" + hiddenLinkMySQLArticle(1<<20), 0},
				{"large article with trailing commented injection", "<style>/* theme */</style>" + hiddenLinkMySQLArticle(1<<20) + `<div style="display:/*x*/none">`, 1},
				{"large article with trailing encoded injection", hiddenLinkMySQLArticle(1<<20) + `<div style="d&#105;splay:none">`, 1},
				{"large article with leading injection", `<div style="left:-9999px">` + hiddenLinkMySQLArticle(1<<20), 1},
				{"joined article with stylesheet comment", "<style>/* theme */</style>" + hiddenLinkMySQLArticle(maxHiddenLinkValueBytes-len("<style>/* theme */</style>")), 0},
				{"joined article with trailing commented injection", hiddenLinkMySQLArticle(maxHiddenLinkValueBytes-128) + `<div style="display:/* x */none">`, 1},
				{"injection outside sampled windows", hiddenLinkMySQLArticle(1<<18) + `<div style="left:-9999px">` + hiddenLinkMySQLArticle(1<<18), 0},
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
		"display/**/:/**/none",
		"display:/* outer /* inner */none",
		"visibility:/* theme */collapse",
		"opacity:/* theme */+0",
		"opacity:/* theme */+.0",
		"opacity:/* theme */-1",
		"opacity:/* theme */1e-400",
		"opacity:\u2009/* theme */\u20090",
		"left:calc(/* layout */-9999px)",
		"margin-top:/* layout */-9999px",
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
			markup := `<div style="` + style + `"><a href="https://spam.example/">x</a></div>`
			if hit := hiddenOffsiteLinks(markup, "shop.example"); len(hit.hosts) != 1 {
				t.Fatal("fixture is not recognized by the existing CSS parser")
			}
			if !candidate(markup) {
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

func TestHiddenLinkCandidateMySQLPreservesCommentBodies(t *testing.T) {
	conn, ctx := hiddenLinkMySQLConn(t)
	for _, mode := range []string{"", "NO_BACKSLASH_ESCAPES"} {
		if _, err := conn.ExecContext(ctx, "SET SESSION sql_mode = ?", mode); err != nil {
			t.Fatal(err)
		}
		for _, body := range []string{"* /", "*\t/", "*\u2009/", "*?/", "*calc(/"} {
			t.Run(mode+fmt.Sprintf("/%x", body), func(t *testing.T) {
				markup := `<div style="display:/* ` + body + ` */none"><a href="https://spam.example/">x</a></div>`
				if hit := hiddenOffsiteLinks(markup, "shop.example"); len(hit.hosts) != 1 {
					t.Fatal("fixture is not hidden by the CSS parser")
				}
				if got := hiddenLinkMySQLCandidate(t, conn, ctx, markup); got != 1 {
					t.Fatal("normalization discarded a hidden commented declaration")
				}
			})
		}
	}
}

func TestHiddenLinkCandidateMySQLJoinedSamples(t *testing.T) {
	conn, ctx := hiddenLinkMySQLConn(t)
	for _, prefix := range []string{`<div sty`, `<div style="displa`, `<div style="display:/* theme `, `<div style="--label:`} {
		t.Run(prefix, func(t *testing.T) {
			var suffix string
			switch prefix {
			case `<div sty`:
				suffix = `le="display:none">`
			case `<div style="displa`:
				suffix = `y:none">`
			case `<div style="display:/* theme `:
				suffix = ` */none">`
			default:
				suffix = strings.Repeat("x", 256) + `;d&#105;splay:none">`
			}
			markup := strings.Repeat("x", maxHiddenLinkSampleBytes-len(prefix)) + prefix + suffix +
				`<a href="https://spam.example/">x</a></div>`
			markup += strings.Repeat("x", maxHiddenLinkValueBytes-len(markup))
			source := hiddenLinkSource{markup: markup[:maxHiddenLinkSampleBytes], tailMarkup: markup[maxHiddenLinkSampleBytes:], valueBytes: len(markup)}
			if hit := hiddenOffsiteLinkSamples(source, []string{"shop.example"}); len(hit.hosts) != 1 {
				t.Fatal("joined samples are not hidden by the CSS parser")
			}
			if got := hiddenLinkMySQLCandidate(t, conn, ctx, markup); got != 1 {
				t.Fatal("SQL discarded a hidden declaration across the sample boundary")
			}
		})
	}
}

func TestHiddenLinkCandidateMySQLLegacyCharset(t *testing.T) {
	conn, ctx := hiddenLinkMySQLConn(t)
	if _, err := conn.ExecContext(ctx, "ALTER TABLE csm_hidden_candidate CONVERT TO CHARACTER SET latin1"); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"", "NO_BACKSLASH_ESCAPES"} {
		if _, err := conn.ExecContext(ctx, "SET SESSION sql_mode = ?", mode); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			markup string
			want   int
		}{
			{`<div style="color:black">ordinary</div>`, 0},
			{`<div style="display:none">`, 1},
			{`<div style="left:&#45;9999px">`, 1},
			{"<div style=\"opacity:\u00a00\">", 1},
			{"<div style=\"opacity:/* theme */\u00a00\">", 1},
			{`<div style="display:/*theme*/block">none</div>`, 0},
		} {
			if got := hiddenLinkMySQLCandidate(t, conn, ctx, tc.markup); got != tc.want {
				t.Fatalf("latin1 candidate = %d, want %d", got, tc.want)
			}
		}
	}
}

func TestHiddenLinkCandidateMySQLEncodingRelation(t *testing.T) {
	conn, ctx := hiddenLinkMySQLConn(t)
	for _, marker := range []string{"&#0", "&#32;", "&#x0", "&#x20;", "&#XAf;", "&colon;", `\69`} {
		t.Run(marker, func(t *testing.T) {
			for _, tc := range []struct {
				markup string
				want   int
			}{
				{`<div style = "--label:` + marker + `">`, 1},
				{`<div style="--label:a&b;` + marker + `">`, 1},
				{`<div title="` + marker + `" style="color:black">`, 0},
				{`<div style="color:black">` + marker + `</div>`, 0},
				{`<div style="color:black">` + marker + `<div style="color:black">`, 0},
				{`<div title="` + marker + `" style="--label:` + marker + `">`, 1},
			} {
				if got := hiddenLinkMySQLCandidate(t, conn, ctx, tc.markup); got != tc.want {
					t.Fatalf("candidate = %d, want %d for %q", got, tc.want, tc.markup)
				}
			}
		})
	}
	for _, marker := range []string{"&#q;", "&#xq;", "&comma;", "a&b"} {
		markup := `<div style="--label:` + marker + `">`
		if got := hiddenLinkMySQLCandidate(t, conn, ctx, markup); got != 0 {
			t.Fatalf("unsupported encoding became a candidate: %q", marker)
		}
	}
}

// The retry selection must fit the server's regex limit for any sampled
// content, so plain and encoded styles stay covered when commented-style
// matching is stopped.
func TestHiddenLinkCandidateMySQLRetrySelectionFitsRegexLimit(t *testing.T) {
	conn, ctx := hiddenLinkMySQLConn(t)
	for _, unit := range []string{`\`, "&#1", "&#x1", "&colon", "?", "=", `style=\`, "/*", "*/", "0", "-", "e", "n", ">"} {
		t.Run(unit, func(t *testing.T) {
			markup := `<div style="color:black">/* x */` + strings.Repeat(unit, 2*maxHiddenLinkSampleBytes/len(unit))
			if _, err := conn.ExecContext(ctx, "DELETE FROM csm_hidden_candidate"); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.ExecContext(ctx, "INSERT INTO csm_hidden_candidate VALUES (?)", markup); err != nil {
				t.Fatal(err)
			}
			var got int
			if err := conn.QueryRowContext(ctx, "SELECT "+hiddenLinkCandidateCondition("markup", false)+" FROM csm_hidden_candidate").Scan(&got); err != nil {
				t.Fatalf("retry selection failed: %v", err)
			}
		})
	}
}

// Exercise the pattern itself so SQL guards and successful prefix matches
// cannot conceal its worst-case work on a fully parsed, joined value.
func TestHiddenLinkCandidateMySQLRetryPatternBudget(t *testing.T) {
	conn, ctx := hiddenLinkMySQLConn(t)
	for _, size := range []int{maxHiddenLinkSampleBytes, maxHiddenLinkValueBytes} {
		for _, unit := range []string{`\`, `\=elyt`, `\aaaa`, `\=ely=ely`, `\style=`, "=elyt", "x"} {
			t.Run(fmt.Sprintf("%d/%s", size, unit), func(t *testing.T) {
				subject := strings.Repeat(unit, size/len(unit)+1)[:size]
				var got int
				if err := conn.QueryRowContext(ctx, "SELECT ? REGEXP ?", subject, hiddenLinkRegexPattern()).Scan(&got); err != nil {
					t.Fatalf("retry pattern exhausted its budget: %v", err)
				}
				if got != 0 {
					t.Fatal("budget fixture matched before scanning its whole subject")
				}
			})
		}
	}
}

func BenchmarkHiddenLinkCandidateMySQL(b *testing.B) {
	conn, ctx := hiddenLinkMySQLConn(b)
	batch := make([]any, 100)
	for i := range batch {
		batch[i] = hiddenLinkMySQLArticle(10 * 1024)
	}
	insert := "INSERT INTO csm_hidden_candidate VALUES " + strings.TrimSuffix(strings.Repeat("(?),", len(batch)), ",")
	for rows := 0; rows < 5000; rows += len(batch) {
		if _, err := conn.ExecContext(ctx, insert, batch...); err != nil {
			b.Fatal(err)
		}
	}
	query := "SELECT COUNT(*) FROM csm_hidden_candidate WHERE " + hiddenLinkCandidateCondition("markup", true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var got int
		if err := conn.QueryRowContext(ctx, query).Scan(&got); err != nil {
			b.Fatal(err)
		}
		if got != 0 {
			b.Fatalf("ordinary articles selected: %d", got)
		}
	}
}

// Content that exhausts commented-style matching must not hide a plain
// declaration in the same install: the retry selects it and coverage stays
// incomplete.
func TestHiddenLinkPostRowsMySQLRetriesAfterRegexTimeout(t *testing.T) {
	conn, ctx := hiddenLinkMySQLConn(t)
	var version string
	if err := conn.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, "CREATE TEMPORARY TABLE csm_retry_posts (ID bigint PRIMARY KEY, post_content longtext, post_status varchar(20), post_type varchar(20)) CHARACTER SET utf8mb4"); err != nil {
		t.Fatal(err)
	}
	markup := `<div style="color:black"></div><script>/*` +
		strings.Repeat("0-", maxHiddenLinkSampleBytes/2) + `*/</script>`
	injected := `<div style="left:-9999px"><a href="https://spam.example/">x</a></div>`
	if _, err := conn.ExecContext(ctx, "INSERT INTO csm_retry_posts VALUES (1, ?, 'publish', 'post'), (2, ?, 'publish', 'post')", markup, injected); err != nil {
		t.Fatal(err)
	}
	mysqlclient.SetPerAccountQueryForTest(func(_ context.Context, _ mysqlclient.Creds, query string, _ ...any) ([]string, error) {
		rows, err := conn.QueryContext(ctx, query)
		if err != nil {
			return nil, err
		}
		defer func() { _ = rows.Close() }()
		columns, err := rows.Columns()
		if err != nil {
			return nil, err
		}
		escape := strings.NewReplacer("\\", "\\\\", "\t", "\\t", "\n", "\\n", "\r", "\\r", "\x00", "\\0")
		var out []string
		for rows.Next() {
			values := make([]sql.RawBytes, len(columns))
			dest := make([]any, len(columns))
			for i := range values {
				dest[i] = &values[i]
			}
			if err := rows.Scan(dest...); err != nil {
				return nil, err
			}
			fields := make([]string, len(values))
			for i, value := range values {
				fields[i] = escape.Replace(string(value))
			}
			out = append(out, strings.Join(fields, "\t"))
		}
		return out, rows.Err()
	})
	t.Cleanup(func() { mysqlclient.SetPerAccountQueryForTest(nil) })

	scanCtx, incomplete := withIncompleteCheckCollector(ctx)
	state := new(dbQueryState)
	creds := wpDBCreds{queryCtx: scanCtx, queryState: state}.withQueryStage("hidden_links")
	rows := hiddenLinkPostRows(creds, "csm_retry_")
	if len(rows) != 1 {
		t.Fatalf("plain declaration was not selected: got %d rows, failures %v", len(rows), state.failures)
	}
	if hit := hiddenOffsiteLinkSamples(rows[0], []string{"shop.example"}); !hit.offScreen {
		t.Fatalf("plain declaration was not detected: %+v", hit)
	}
	if state.halted {
		t.Fatal("regex timeout halted the install")
	}
	if strings.Contains(version, "MariaDB") {
		return
	}
	if !state.failed || !incomplete.contains("db_content") {
		t.Fatal("stopped commented-style matching did not leave coverage incomplete")
	}
	if state.failures["stage=hidden_links class=timeout code=3699"] != 1 {
		t.Fatalf("failures = %v, want one recorded regex timeout", state.failures)
	}
}

// SQL candidates must include the forms accepted by the final Go parser.
func TestHiddenLinkCandidateMySQLParserForms(t *testing.T) {
	conn, ctx := hiddenLinkMySQLConn(t)
	for _, mode := range []string{"", "NO_BACKSLASH_ESCAPES"} {
		if _, err := conn.ExecContext(ctx, "SET SESSION sql_mode = ?", mode); err != nil {
			t.Fatal(err)
		}
		for _, style := range []string{"display:none", "visibility:hidden", "visibility:collapse", "opacity:+.0", "opacity:-1e400", "left:calc(-9999px)", "margin-top:-100em"} {
			for i := 0; i <= len(style); i++ {
				for _, gap := range []string{"/**/", "/* * / */", "/* *calc(/ */", "\u2009", "\u0085", "\u000b"} {
					mutated := style[:i] + gap + style[i:]
					markup := `<div style="` + mutated + `"><a href="https://spam.example/">x</a></div>`
					if len(hiddenOffsiteLinks(markup, "shop.example").hosts) == 0 {
						continue
					}
					if hiddenLinkMySQLCandidate(t, conn, ctx, markup) != 1 {
						t.Errorf("lost %q", mutated)
					}
				}
			}
			for i := 0; i < len(style); i++ {
				for _, marker := range []string{fmt.Sprintf("&#%d;", style[i]), fmt.Sprintf("&#x%x;", style[i]), fmt.Sprintf(`\%x `, style[i])} {
					markup := `<div STYLE="` + strings.ToUpper(style[:i]+marker+style[i+1:]) + `"><a href="https://spam.example/">x</a></div>`
					if len(hiddenOffsiteLinks(markup, "shop.example").hosts) == 0 {
						continue
					}
					if hiddenLinkMySQLCandidate(t, conn, ctx, markup) != 1 {
						t.Errorf("lost %q", markup)
					}
				}
			}
		}
	}
}
