package checks

import "testing"

func TestIsWPVersionDataBytesComplete(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       bool
	}{
		{"minimal", "<?php $wp_version = '7.1';", true},
		{"localized", "<?php /* WordPress Version */\n$wp_version = '7.1'; $wp_db_version = 60000; $tinymce_version = '49110-20250317'; $required_php_version = '7.4'; $required_php_extensions = array('json', 'hash',); $required_mysql_version = '5.5.5'; $wp_local_package = 'ro_RO';", true},
		{"array shorthand", "<?php $wp_version = '7.1'; $required_php_extensions = ['json'];", true},
		{"empty", "", false},
		{"no version", "<?php $wp_db_version = 60000;", false},
		{"unknown variable", "<?php $wp_version = '7.1'; $_POST = [];", false},
		{"variable variable", "<?php $$wp_version = '7.1';", false},
		{"offset assignment", "<?php $wp_version[system('id')] = '7.1';", false},
		{"reference", "<?php $wp_version = &$payload;", false},
		{"function", "<?php $wp_version = phpversion();", false},
		{"interpolation", "<?php $wp_version = \"${system('id')}\";", false},
		{"appended code", "<?php $wp_version = '7.1'; system($_POST['c']);", false},
		{"attribute conceals code", "<?php $wp_version = '7.1'; #[Example] function example() {} system($_POST['c']);", false},
		{"closing tag", "<?php $wp_version = '7.1'; ?><?php system($_POST['c']);", false},
		{"missing semicolon", "<?php $wp_version = '7.1'", false},
		{"array call", "<?php $wp_version = '7.1'; $required_php_extensions = [system('id')];", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsWPVersionDataBytesComplete([]byte(tc.body), true); got != tc.want {
				t.Fatalf("recognized = %v, want %v", got, tc.want)
			}
			if IsWPVersionDataBytesComplete([]byte(tc.body), false) {
				t.Fatal("incomplete snapshot accepted")
			}
		})
	}
}
