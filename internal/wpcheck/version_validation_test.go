package wpcheck

import (
	"strings"
	"testing"
)

// version.php is tenant-writable. Its two strings used to reach a root-written
// cache filename and an unescaped query string verbatim, so a tenant could
// steer the checksum cache write toward another path or rewrite the request.
// Both values are validated where they are parsed.
func TestParseVersionContentRejectsHostileStrings(t *testing.T) {
	hostile := []string{
		"<?php $wp_version = '6.5'; $wp_local_package = '../../../../etc/docker/daemon';",
		"<?php $wp_version = '6.5&locale=x'; $wp_local_package = 'en_US';",
		"<?php $wp_version = '6.5'; $wp_local_package = 'en/US';",
		"<?php $wp_version = '6.5'; $wp_local_package = 'en_US#x';",
		"<?php $wp_version = '../6.5';",
	}
	for _, src := range hostile {
		if v, l, err := ParseVersionContent([]byte(src)); err == nil {
			t.Fatalf("accepted hostile version.php %q as version=%q locale=%q", src, v, l)
		}
	}
}

func TestParseVersionContentAcceptsRealVersionsAndLocales(t *testing.T) {
	cases := []struct{ src, version, locale string }{
		{"<?php $wp_version = '6.5.2';", "6.5.2", "en_US"},
		{"<?php $wp_version = '6.7-RC1'; $wp_local_package = 'de_DE_formal';", "6.7-RC1", "de_DE_formal"},
		{"<?php $wp_version = '6.8-alpha-59245'; $wp_local_package = 'pt_BR';", "6.8-alpha-59245", "pt_BR"},
		{"<?php $wp_version = '6.6'; $wp_local_package = 'ary';", "6.6", "ary"},
		{"<?php $wp_version = '6.7.1'; $wp_local_package = 'es_419';", "6.7.1", "es_419"},
	}
	for _, tc := range cases {
		v, l, err := ParseVersionContent([]byte(tc.src))
		if err != nil || v != tc.version || l != tc.locale {
			t.Fatalf("%q -> version=%q locale=%q err=%v, want %q/%q", tc.src, v, l, err, tc.version, tc.locale)
		}
	}
}

func TestChecksumAPIURLEscapesQueryValues(t *testing.T) {
	u := checksumAPIURL("6.5", "a&locale=b")
	if !strings.Contains(u, "locale=a%26locale%3Db") {
		t.Fatalf("query values not escaped: %s", u)
	}
}
