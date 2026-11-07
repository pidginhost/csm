package checks

import (
	"slices"
	"testing"
)

// attackCorpusDeepCheckKind classifies every deep-tier check for the attack
// corpus. A file check reads account tree content and needs no network,
// database, mail, package or system state, so the corpus replays it on a temp
// account tree. A host check cannot be replayed there. The comment on each
// entry is the reason.
var attackCorpusDeepCheckKind = map[string]string{
	"filesystem":            "file", // backdoor names under ~/.config, setuid files in homes; the host temp dirs it also globs are subtracted by the baseline run
	"webshells":             "file", // known web shell file and directory names in account doc roots
	"htaccess":              "file", // .htaccess directives in account doc roots
	"exposed_files":         "host", // confirms each exposure with a live request through its own HTTP transport
	"wp_core":               "host", // runs wp-cli core verify-checksums, which fetches checksums from wordpress.org
	"file_index":            "file", // diffs the account tree against the file index kept in the state dir
	"php_content":           "file", // PHP content in account doc roots; rolling cursor in the state database
	"yara_deep":             "file", // YARA and PHP/JS taint over account doc roots
	"phishing":              "file", // phishing pages, kit directories and kit zips in account doc roots
	"nulled_plugins":        "file", // crack signatures in WordPress plugin main files
	"rpm_integrity":         "host", // verifies system packages with rpm or dpkg
	"group_writable_php":    "file", // PHP file modes in public_html; the web server group comes from /etc/group
	"open_basedir":          "host", // CageFS state, cPanel user records and EA-PHP config
	"symlink_attacks":       "file", // symlinks in public_html that leave the account
	"php_config_changes":    "file", // .user.ini and php.ini in account doc roots, hashes in the state store
	"dns_zones":             "host", // zone files in /var/named
	"ssl_certs":             "host", // AutoSSL logs under /var/cpanel
	"waf_status":            "host", // ModSecurity install and web server config, which it may also manage
	"db_content":            "host", // WordPress database content over MySQL
	"db_content_drupal":     "host", // Drupal database content over MySQL
	"db_content_joomla":     "host", // Joomla database content over MySQL
	"db_content_magento":    "host", // Magento database content over MySQL
	"db_content_opencart":   "host", // OpenCart database content over MySQL
	"db_objects":            "host", // triggers, events and routines over MySQL
	"admin_overlap":         "host", // WordPress admin emails from site databases
	"credential_reuse":      "host", // admin password hashes from site databases
	"email_content":         "host", // outbound mail from the Exim log and spool
	"outdated_plugins":      "host", // wp-cli plugin inventory and api.wordpress.org versions
	"wp_plugin_inventory":   "host", // verification history of the wp-cli plugin inventory
	"vulnerable_plugins":    "host", // wp-cli plugin inventory against the vulnerability feed
	"vulnerable_timthumb":   "file", // TimThumb scripts in account doc roots
	"supply_chain":          "file", // dependency lockfiles in account trees against an advisory file in the state dir; dormant without one, as on a fresh install
	"email_weak_password":   "host", // mailbox password hashes, mail credentials rather than web content
	"email_forwarder_audit": "host", // mail forwarders in /etc/valiases
	"email_mail_filters":    "host", // Exim filters in /etc/vfilters and Sieve scripts
	"perf_php_handler":      "host", // LiteSpeed PHP handlers through whmapi1
	"perf_mysql_config":     "host", // MySQL server variables
	"perf_redis_config":     "host", // Redis server config
	"perf_error_logs":       "file", // error_log sizes under account doc roots
	"perf_wp_config":        "file", // wp-config.php constants under account doc roots
	"perf_wp_transients":    "host", // transient sizes from site databases
	"perf_wp_cron":          "file", // WP-Cron settings in wp-config.php under account doc roots
	"perf_wp_loopback":      "host", // web server access logs
	"perf_wp_myisam":        "host", // table engines from site databases
}

// attackCorpusTierChecks is the deep tier the corpus replays: deepChecks()
// filtered to file checks, in tier order.
func attackCorpusTierChecks() []namedCheck {
	var out []namedCheck
	for _, c := range deepChecks() {
		if attackCorpusDeepCheckKind[c.name] == "file" {
			out = append(out, c)
		}
	}
	return out
}

// A new deep check fails here until it is classified, so it cannot stay out
// of the corpus replay unnoticed.
func TestAttackCorpusDeepChecksClassified(t *testing.T) {
	deep := map[string]bool{}
	for _, c := range deepChecks() {
		deep[c.name] = true
		if kind := attackCorpusDeepCheckKind[c.name]; kind != "file" && kind != "host" {
			t.Errorf("deep check %s is classified %q, want file or host", c.name, kind)
		}
	}
	for name := range attackCorpusDeepCheckKind {
		if !deep[name] {
			t.Errorf("%s is classified but is not a deep check", name)
		}
	}
	var replayed []string
	for _, c := range attackCorpusTierChecks() {
		replayed = append(replayed, c.name)
	}
	// The only path that runs PHP and JS taint.
	if !slices.Contains(replayed, "yara_deep") {
		t.Errorf("replayed tier %v lacks yara_deep", replayed)
	}
}
