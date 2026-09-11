package signatures

import (
	"fmt"
	"strings"
	"testing"
)

// Exercise the independent creation branches and their boundaries. Keeping the
// role separate prevents the WP_User/set_role chain from masking a missing arm.
func wpAdminCreationSamples() []struct {
	name   string
	source string
	want   bool
} {
	return []struct {
		name   string
		source string
		want   bool
	}{
		{"empty", "", false},
		{"function_only", `wp_create_user($login, $password);`, false},
		{"literal_create", `wp_create_user('fixture-user', 'fixture-password');`, true},
		{"literal_create_unicode_data", "wp_create_user('\u017f', 'bb');", true},
		{"literal_create_vertical_tab", "wp_create_user\v(\v'fixture-user'\v,\v'fixture-password');", true},
		{"literal_create_limit", `wp_create_user('` + strings.Repeat("a", 40) + `', 'fixture-password');`, true},
		{"literal_create_over_limit", `wp_create_user('` + strings.Repeat("a", 41) + `', 'fixture-password');`, false},
		{"literal_insert_before_call", `$data = ['user_pass' => 'fixture-password']; wp_insert_user($data);`, true},
		{"literal_insert_vertical_tab", "$data = ['user_pass'\v=>\v'fixture-password']; wp_insert_user($data);", true},
		{"literal_insert_after_call", `function create($data) { wp_insert_user($data); } $data = ['user_login' => 'fixture-user'];`, true},
		{"literal_insert_overlapping_token", `$data = ['user_pass' => 'wp_insert_user'];`, true},
		{"literal_insert_overlapping_token_offset", `$data = ['user_pass' => 'xwp_insert_user'];`, true},
		{"literal_insert_minimum", `wp_insert_user($data); $data = ['user_pass' => 'ab'];`, true},
		{"literal_insert_unicode_data", "wp_insert_user($data); $data = ['user_pass' => '\u017f\u017f'];", true},
		{"literal_insert_too_short", `wp_insert_user($data); $data = ['user_pass' => 'a'];`, false},
		{"literal_insert_without_insert", `$data = ['user_pass' => 'fixture-password']; wp_create_user($login, $password);`, false},
		{"request_create", `wp_create_user($_POST['nu'], $_GET['np']);`, true},
		{"request_create_whitespace", `wp_create_user ( $_REQUEST ['nu'], $_POST ['np'] );`, true},
		{"request_create_vertical_tab", "wp_create_user\v(\v$_REQUEST\v['nu'],\v$_POST\v['np']);", true},
		{"request_create_limit", `wp_create_user($_POST[` + strings.Repeat("a", 80) + `, $_GET['np']);`, true},
		{"request_create_over_limit", `wp_create_user($_POST[` + strings.Repeat("a", 81) + `, $_GET['np']);`, false},
		{"generated_import_password", `wp_create_user($_POST['user_new'][$i], wp_generate_password());`, false},
		{"only_password_from_request", `wp_create_user($login, $_POST['np']);`, false},
		{"cookie_create", `wp_create_user($_COOKIE['nu'], $_COOKIE['np']);`, false},
		{"variable_create_chain", `$uid = wp_create_user($login, $password); $u = new WP_User($uid); $u->set_role('administrator');`, false},
		{"request_insert_password", `wp_insert_user(['user_pass' => $_REQUEST['p']]);`, true},
		{"request_insert_vertical_tab", "wp_insert_user\v(['user_pass'\v=>\v$_REQUEST\v['p']]);", true},
		{"request_insert_login", `wp_insert_user(['user_login' => $_GET['u']]);`, true},
		{"request_insert_nonadmin_prefix", `wp_insert_user(['user_pass' => $_POST['p'], 'role' => 'administrator_custom']);`, true},
		{"request_insert_limit", `wp_insert_user(` + strings.Repeat(" ", 400) + `'user_pass' => $_POST['p']);`, true},
		{"request_insert_over_limit", `wp_insert_user(` + strings.Repeat(" ", 401) + `'user_pass' => $_POST['p']);`, false},
		{"request_insert_semicolon", `wp_insert_user($data); $data = ['user_pass' => $_POST['p']];`, false},
		{"request_insert_other_field", `wp_insert_user(['display_name' => $_POST['n']]);`, false},
		{"cookie_insert", `wp_insert_user(['user_pass' => $_COOKIE['p']]);`, false},
		{"variable_insert_role", `wp_insert_user(['user_login' => $login, 'user_pass' => $password, 'role' => 'administrator']);`, false},
		{"indirect_before_call", `$login = $_POST['username']; $password = $_GET['password']; wp_create_user($login, $password);`, true},
		{"indirect_vertical_tab", "$login = $_POST\v[\v'username']; $password = $_GET\v[\v'password']; wp_create_user($login, $password);", true},
		{"indirect_reverse_vertical_tab", "$password = $_POST\v[\v'password']; $login = $_GET\v[\v'username']; wp_insert_user($data);", true},
		{"indirect_after_call", `function create($l, $p) { wp_create_user($l, $p); } $login = $_GET['login']; $password = $_REQUEST['pass'];`, true},
		{"indirect_straddling_call", `$login = $_POST['user']; wp_create_user($login, $_GET['password']);`, true},
		{"indirect_reverse", `$password = $_POST['pass']; $login = $_REQUEST['username']; wp_insert_user($data);`, true},
		{"indirect_reverse_straddling_call", `$password = $_POST['password']; wp_insert_user(['user_login' => $_GET['user']]);`, true},
		{"indirect_limit", `$_POST['login'` + strings.Repeat(" ", 300) + `$_GET['pass']; wp_create_user($login, $password);`, true},
		{"indirect_over_limit", `$_POST['login'` + strings.Repeat(" ", 301) + `$_GET['pass']; wp_create_user($login, $password);`, false},
		{"indirect_without_function", `$login = $_POST['user']; $password = $_GET['pass'];`, false},
		{"indirect_cookie", `$login = $_COOKIE['user']; $password = $_COOKIE['pass']; wp_create_user($login, $password);`, false},
		{"multiple_creation_shapes", `wp_create_user('fixture-user', 'fixture-password'); wp_insert_user(['user_pass' => $_POST['p']]);`, true},
	}
}

func checkWPAdminCreationSamples(t *testing.T, match func(*testing.T, string) bool) {
	t.Helper()
	roles := []struct {
		name   string
		source string
		want   bool
	}{
		{"no_role", "", false},
		{"set_role", `$u->set_role('administrator');`, true},
		{"set_role_vertical_tab", "$u->set_role\v(\v'administrator');", true},
		{"array_role", `$data = ['role' => 'administrator'];`, true},
		{"array_role_vertical_tab", "$data = ['role'\v=>\v'administrator'];", true},
		{"both_roles", `$u->set_role('administrator'); $data = ['role' => 'administrator'];`, true},
		{"other_role", `$u->set_role('subscriber');`, false},
		{"array_role_prefix", `$data = ['role' => 'administrator_custom'];`, false},
	}
	for _, sample := range wpAdminCreationSamples() {
		t.Run(sample.name, func(t *testing.T) {
			for _, role := range roles {
				t.Run(role.name, func(t *testing.T) {
					// Some negative creation cases already contain a role token.
					want := sample.want && role.want
					for _, source := range []string{
						"<?php\n" + role.source + "\n" + sample.source,
						"<?php\n" + sample.source + "\n" + role.source,
						strings.ToUpper("<?php\n" + role.source + "\n" + sample.source),
					} {
						if got := match(t, source); got != want {
							t.Errorf("match = %t, want %t for %q", got, want, source)
						}
					}
				})
			}
		})
	}
	t.Run("case_folding", func(t *testing.T) {
		checkWPAdminCreationCaseFolding(t, match)
	})
}

// Go folds the Unicode long s into ASCII s/S; YARA nocase only folds ASCII.
// Every s in these samples is part of a required token, so replacing one must
// invalidate that shape. Check each position to keep either gate from masking
// a Unicode token accepted by the other gate.
func checkWPAdminCreationCaseFolding(t *testing.T, match func(*testing.T, string) bool) {
	t.Helper()
	creations := []string{
		`wp_create_user('aa', 'bb');`,
		`wp_insert_user($d); ['user_pass' => 'bb'];`,
		`['user_login' => 'aa']; wp_insert_user($d);`,
		`wp_create_user($_POST['n'], $_REQUEST['p']);`,
		`wp_insert_user(['user_pass' => $_POST['p']]);`,
		`wp_insert_user(['user_login' => $_GET['n']]);`,
		`$_POST['username']; $_GET['password']; wp_create_user($l, $p);`,
		`$_REQUEST['pass']; $_GET['user']; wp_insert_user($d);`,
	}
	for creationIndex, creation := range creations {
		for roleIndex, role := range []string{`set_role('administrator');`, `['role' => 'administrator'];`} {
			source := "<?php " + creation + " " + role
			for _, ascii := range []string{source, strings.ToUpper(source)} {
				if !match(t, ascii) {
					t.Errorf("ASCII case variant did not match: %q", ascii)
				}
				for offset, ch := range ascii {
					if ch != 's' && ch != 'S' {
						continue
					}
					t.Run(fmt.Sprintf("creation_%d_role_%d_offset_%d_%c", creationIndex, roleIndex, offset, ch), func(t *testing.T) {
						variant := ascii[:offset] + "\u017f" + ascii[offset+1:]
						if match(t, variant) {
							t.Errorf("Unicode case variant matched an ASCII token: %q", variant)
						}
					})
				}
			}
		}
	}
}

func TestExploitWpAdminCreation_CreationShapes(t *testing.T) {
	scanner := loadRepoScanner(t)
	if err := scanner.LoadError(); err != nil {
		t.Fatalf("production regex compilation failed: %v", err)
	}
	// Load the whole ruleset to catch RE2 compilation errors, then isolate this
	// rule so the role/creation matrix does not repeatedly scan unrelated rules.
	var target *Scanner
	for _, rule := range scanner.rules {
		if rule.Name == "exploit_wp_admin_creation" {
			target = &Scanner{rules: []Rule{rule}}
			break
		}
	}
	if target == nil {
		t.Fatal("production WordPress admin-creation rule is missing")
	}
	checkWPAdminCreationSamples(t, func(_ *testing.T, source string) bool {
		return hasRule(target.ScanContent([]byte(source), ".php"), "exploit_wp_admin_creation")
	})
}
