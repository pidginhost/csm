package checks

import (
	"slices"

	"github.com/pidginhost/csm/internal/admission"
)

// ProducerEntry is one producer of admission evidence: what it registers,
// and the parser its observations name.
type ProducerEntry struct {
	Spec   admission.ProducerSpec
	Parser admission.ParserRef
}

// Producer IDs the readers name when they stamp an observation.
const (
	ProducerSSHLog          admission.ProducerID = "sshd_log"
	ProducerSSHLoginScan    admission.ProducerID = "ssh_login_scan"
	ProducerPAMSocket       admission.ProducerID = "pam_socket"
	ProducerFTPLog          admission.ProducerID = "ftp_log"
	ProducerFTPScan         admission.ProducerID = "ftp_scan"
	ProducerEximLog         admission.ProducerID = "exim_log"
	ProducerEximHistory     admission.ProducerID = "exim_history"
	ProducerMailLog         admission.ProducerID = "mail_log"
	ProducerAccessLog       admission.ProducerID = "access_log"
	ProducerDomlogScan      admission.ProducerID = "domlog_scan"
	ProducerModSecLog       admission.ProducerID = "modsec_log"
	ProducerModSecAuditScan admission.ProducerID = "modsec_audit_scan"
	ProducerCpanelAccessLog admission.ProducerID = "cpanel_access_log"
	ProducerCpanelScan      admission.ProducerID = "cpanel_access_scan"
	ProducerReputationScan  admission.ProducerID = "reputation_scan"
	ProducerThreatScan      admission.ProducerID = "threat_scan"
	ProducerConnectionScan  admission.ProducerID = "connection_scan"
)

// producerTable lists every producer of address evidence. Realtime and
// scheduled readers are separate producers because each has its own
// observation stream. Admission has no realtime entry: both reach the
// single-address scan admission. Claims are the kinds a producer's findings
// may carry: a vhost log names a domain, a login names an authenticated
// account or mailbox, a request names a host it chose itself.
var producerTable = []ProducerEntry{
	{admission.ProducerSpec{ID: ProducerSSHLog, Entry: admission.EntryScan, Observation: admission.ObservationLogCursor,
		Checks: []string{"ssh_login_unknown_ip"}, Claims: []admission.ClaimKind{admission.ClaimAccount}},
		admission.ParserRef{Name: "sshd", Version: 1}},
	{admission.ProducerSpec{ID: ProducerSSHLoginScan, Entry: admission.EntryScan, Observation: admission.ObservationLogCursor,
		Checks: []string{"ssh_login_unknown_ip"}, Claims: []admission.ClaimKind{admission.ClaimAccount}},
		admission.ParserRef{Name: "sshd", Version: 1}},
	{admission.ProducerSpec{ID: ProducerPAMSocket, Entry: admission.EntryScan, Observation: admission.ObservationEventSeq,
		Checks: []string{"pam_bruteforce", "credential_stuffing"}},
		admission.ParserRef{Name: "pam_csm", Version: 1}},
	{admission.ProducerSpec{ID: ProducerFTPLog, Entry: admission.EntryScan, Observation: admission.ObservationLogCursor,
		Checks: []string{"ftp_auth_failure_realtime"}},
		admission.ParserRef{Name: "pureftpd", Version: 1}},
	{admission.ProducerSpec{ID: ProducerFTPScan, Entry: admission.EntryScan, Observation: admission.ObservationLogCursor,
		Checks: []string{"ftp_bruteforce"}},
		admission.ParserRef{Name: "pureftpd", Version: 1}},
	{admission.ProducerSpec{ID: ProducerEximLog, Entry: admission.EntryScan, Observation: admission.ObservationLogCursor,
		Checks: []string{"smtp_bruteforce", "smtp_subnet_spray", "smtp_probe_abuse", "email_cloud_relay_abuse"},
		Claims: []admission.ClaimKind{admission.ClaimAccount, admission.ClaimMailbox}},
		admission.ParserRef{Name: "exim", Version: 1}},
	{admission.ProducerSpec{ID: ProducerEximHistory, Entry: admission.EntryScan, Observation: admission.ObservationScanPass,
		Checks: []string{"email_cloud_relay_abuse"}, Claims: []admission.ClaimKind{admission.ClaimAccount, admission.ClaimMailbox}},
		admission.ParserRef{Name: "exim", Version: 1}},
	{admission.ProducerSpec{ID: ProducerMailLog, Entry: admission.EntryScan, Observation: admission.ObservationLogCursor,
		Checks: []string{"mail_bruteforce", "mail_subnet_spray", "mail_account_compromised"},
		Claims: []admission.ClaimKind{admission.ClaimAccount, admission.ClaimMailbox}},
		admission.ParserRef{Name: "dovecot", Version: 1}},
	{admission.ProducerSpec{ID: ProducerAccessLog, Entry: admission.EntryScan, Observation: admission.ObservationLogCursor,
		Checks: []string{"wp_login_bruteforce", "xmlrpc_abuse", "admin_panel_bruteforce"}},
		admission.ParserRef{Name: "access_log", Version: 1}},
	{admission.ProducerSpec{ID: ProducerDomlogScan, Entry: admission.EntryScan, Observation: admission.ObservationScanPass,
		Checks: []string{"wp_login_bruteforce", "xmlrpc_abuse", "wp_user_enumeration", "http_request_flood", "http_ua_spoof",
			"http_scanner_profile", "http_claimed_bot_unverified", "http_asn_crawl"},
		Claims: []admission.ClaimKind{admission.ClaimDomain}},
		admission.ParserRef{Name: "access_log", Version: 1}},
	{admission.ProducerSpec{ID: ProducerModSecLog, Entry: admission.EntryScan, Observation: admission.ObservationLogCursor,
		Checks: []string{"modsec_block_escalation", "modsec_csm_block_escalation"}, Claims: []admission.ClaimKind{admission.ClaimRequestName}},
		admission.ParserRef{Name: "modsec", Version: 1}},
	{admission.ProducerSpec{ID: ProducerModSecAuditScan, Entry: admission.EntryScan, Observation: admission.ObservationScanPass,
		Checks: []string{"waf_attack_blocked"}},
		admission.ParserRef{Name: "modsec_audit", Version: 1}},
	{admission.ProducerSpec{ID: ProducerCpanelAccessLog, Entry: admission.EntryScan, Observation: admission.ObservationLogCursor,
		Checks: []string{"api_auth_failure_realtime"}},
		admission.ParserRef{Name: "cpsrvd", Version: 1}},
	{admission.ProducerSpec{ID: ProducerCpanelScan, Entry: admission.EntryScan, Observation: admission.ObservationScanPass,
		Checks: []string{"api_auth_failure", "webmail_bruteforce"}},
		admission.ParserRef{Name: "cpsrvd", Version: 1}},
	{admission.ProducerSpec{ID: ProducerReputationScan, Entry: admission.EntryScan, Observation: admission.ObservationScanPass,
		Checks: []string{"ip_reputation"}},
		admission.ParserRef{Name: "reputation", Version: 1}},
	{admission.ProducerSpec{ID: ProducerThreatScan, Entry: admission.EntryScan, Observation: admission.ObservationScanPass,
		Checks: []string{"local_threat_score"}},
		admission.ParserRef{Name: "attackdb", Version: 1}},
	{admission.ProducerSpec{ID: ProducerConnectionScan, Entry: admission.EntryScan, Observation: admission.ObservationScanPass,
		Checks: []string{"c2_connection"}},
		admission.ParserRef{Name: "proc_net_tcp", Version: 1}},
}

// ProducerTable returns a copy of the producer table.
func ProducerTable() []ProducerEntry {
	out := make([]ProducerEntry, len(producerTable))
	for i, p := range producerTable {
		out[i] = p
		out[i].Spec.Checks = slices.Clone(p.Spec.Checks)
		out[i].Spec.Claims = slices.Clone(p.Spec.Claims)
	}
	return out
}

// ProducerParser returns the parser a producer's observations name.
func ProducerParser(id admission.ProducerID) (admission.ParserRef, bool) {
	for _, p := range producerTable {
		if p.Spec.ID == id {
			return p.Parser, true
		}
	}
	return admission.ParserRef{}, false
}
