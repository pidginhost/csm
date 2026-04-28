package checks

import (
	"errors"
	"strings"
	"testing"
)

func TestQuoteIdentAccepts(t *testing.T) {
	cases := []string{
		"wp_options",
		"trigger_after_insert",
		"my_db",
		"alice_wp_2023",
		"name_with_$dollar",
		"X",
		"_leading_underscore",
		"$starts_with_dollar",
		"1234numeric",
	}
	for _, c := range cases {
		got, err := QuoteIdent(c)
		if err != nil {
			t.Errorf("QuoteIdent(%q) err = %v, want nil", c, err)
			continue
		}
		want := "`" + c + "`"
		if got != want {
			t.Errorf("QuoteIdent(%q) = %q, want %q", c, got, want)
		}
	}
}

func TestQuoteIdentRejectsEmpty(t *testing.T) {
	_, err := QuoteIdent("")
	if !errors.Is(err, errEmptyIdent) {
		t.Errorf("QuoteIdent(\"\") err = %v, want errEmptyIdent", err)
	}
}

func TestQuoteIdentRejectsTooLong(t *testing.T) {
	long := strings.Repeat("a", mysqlIdentMaxLen+1)
	_, err := QuoteIdent(long)
	if !errors.Is(err, errLongIdent) {
		t.Errorf("QuoteIdent(long) err = %v, want errLongIdent", err)
	}
}

func TestQuoteIdentRejectsInjection(t *testing.T) {
	cases := []string{
		"foo`bar",          // backtick break
		"foo;DROP TABLE x", // statement separator
		"foo bar",          // space
		"foo\nbar",         // newline
		"foo'bar",          // quote
		"foo\"bar",         // double quote
		"foo.bar",          // dotted name (operator must split schema/object)
		"foo-bar",          // hyphen
		"foo/bar",          // slash
		"\x00poison",       // NUL
		"тable",            // non-ASCII letter
	}
	for _, c := range cases {
		_, err := QuoteIdent(c)
		if !errors.Is(err, errInvalidIdent) {
			t.Errorf("QuoteIdent(%q) err = %v, want errInvalidIdent", c, err)
		}
	}
}

func TestQuoteIdentBacktickInResultIsClosingOnly(t *testing.T) {
	// Sanity: the function never produces a string with an unmatched
	// backtick that could break an enclosing query. Re-quoting a known
	// good name should be idempotent under "strip outer ticks then
	// quote again".
	q, err := QuoteIdent("wp_options")
	if err != nil {
		t.Fatalf("QuoteIdent: %v", err)
	}
	if strings.Count(q, "`") != 2 {
		t.Errorf("expected exactly 2 backticks in %q", q)
	}
	if !strings.HasPrefix(q, "`") || !strings.HasSuffix(q, "`") {
		t.Errorf("expected leading and trailing backtick in %q", q)
	}
}
