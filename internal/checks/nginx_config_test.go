package checks

import (
	"path/filepath"
	"reflect"
	"testing"
)

func nginxNames(ds []nginxDirective) []string {
	var out []string
	for _, d := range ds {
		out = append(out, d.Name)
	}
	return out
}

// Comments and quoted text never start a directive, and quoted arguments
// keep their escaped characters.
func TestNginxDirectivesSkipCommentsAndQuotes(t *testing.T) {
	text := "# set_real_ip_from 192.0.2.0/24;\nlog_format peer '$remote_addr \\' set_real_ip_from;' \"a;b\";\nhttp { server { listen 80; } }\n"
	got, ok := parseNginxDirectives(text, "nginx.conf")
	if !ok {
		t.Fatal("well-formed text reported as incomplete")
	}
	if names := nginxNames(got); !reflect.DeepEqual(names, []string{"log_format", "http", "server", "listen"}) {
		t.Fatalf("directives = %v", names)
	}
	if args := got[0].Args; !reflect.DeepEqual(args, []string{"peer", "$remote_addr ' set_real_ip_from;", "a;b"}) {
		t.Fatalf("log_format args = %q", args)
	}
}

func TestNginxDirectivesRefuseUnterminatedText(t *testing.T) {
	for _, text := range []string{"http {", "}", "listen 80", "log_format x 'open;", ";", "http { server { }", `"" x;`, `''{}`} {
		got, ok := parseNginxDirectives(text, "nginx.conf")
		if ok {
			t.Errorf("parseNginxDirectives(%q) reported complete", text)
		}
		for _, d := range got {
			if d.Name == "" {
				t.Errorf("parseNginxDirectives(%q) returned a directive without a name", text)
			}
		}
	}
}

// Includes expand in place, relative to the main file's directory, in
// sorted glob order; a glob matching nothing is complete.
func TestNginxDirectivesExpandIncludesInPlace(t *testing.T) {
	dir := t.TempDir()
	writeRewriteFile(t, dir, "conf.d/b.conf", "b_directive;\n")
	writeRewriteFile(t, dir, "conf.d/a.conf", "a_directive;\n")
	main := writeRewriteFile(t, dir, "nginx.conf", "first;\nhttp { include conf.d/*.conf; include empty.d/*; }\nlast;\n")
	got, complete := nginxDirectives(main)
	if !complete {
		t.Fatal("complete tree reported as incomplete")
	}
	if names := nginxNames(got); !reflect.DeepEqual(names, []string{"first", "http", "a_directive", "b_directive", "last"}) {
		t.Fatalf("directives = %v", names)
	}
	if got[2].File != filepath.Join(dir, "conf.d/a.conf") {
		t.Fatalf("included directive names file %q", got[2].File)
	}
}

// Tokens follow nginx: a hash or quote counts only at a token boundary, a
// backslash escapes the next character and only \", \', \\, \t, \r and
// \n decode, "${" stays in a variable, and text glued to a closing quote
// is refused.
func TestNginxDirectivesTokenBoundaries(t *testing.T) {
	for _, tc := range []struct {
		text string
		args []string
	}{
		{"a foo#bar;", []string{"foo#bar"}},
		{`a "x y" 'z';`, []string{"x y", "z"}},
		{`a "q\"q" 'it\'s';`, []string{`q"q`, "it's"}},
		{`a esc\ aped;`, []string{`esc\ aped`}},
		{"a ${host}x;", []string{"${host}x"}},
		{`a tab\tc back\\s other\q;`, []string{"tab\tc", `back\s`, `other\q`}},
		{"a b};", []string{"b}"}},
		{`a "b")suffix;`, []string{"b", ")suffix"}},
	} {
		got, ok := parseNginxDirectives(tc.text, "nginx.conf")
		if !ok || len(got) != 1 || got[0].Name != "a" || !reflect.DeepEqual(got[0].Args, tc.args) {
			t.Errorf("parseNginxDirectives(%q) = %+v, %v; want a %q", tc.text, got, ok, tc.args)
		}
	}
	if got, ok := parseNginxDirectives(`if ($a = "b") { x; }`, "nginx.conf"); !ok || !reflect.DeepEqual(nginxNames(got), []string{"if", "x"}) {
		t.Errorf("if block = %+v, %v", got, ok)
	}
	for _, text := range []string{`a "x"y;`, "a 'open;", `a \`, `a "x"}`} {
		if _, ok := parseNginxDirectives(text, "nginx.conf"); ok {
			t.Errorf("parseNginxDirectives(%q) reported complete", text)
		}
	}
}
