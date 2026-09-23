package privops

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/pidginhost/csm/internal/config"
)

func TestOperationsOwnTheirSlices(t *testing.T) {
	got := Operations()
	for i := range got {
		got[i].Privileges = slices.Clone(got[i].Privileges)
		got[i].Writes = slices.Clone(got[i].Writes)
	}
	// Mutate a separate returned inventory, not the expected snapshot.
	mutated := Operations()
	for i := range mutated {
		mutated[i].Privileges[0] = "changed"
		if len(mutated[i].Writes) != 0 {
			mutated[i].Writes[0] = "/changed"
		}
	}
	t.Cleanup(func() { operations = got })
	if !reflect.DeepEqual(Operations(), got) {
		t.Error("a caller can corrupt the shared privilege and write claims")
	}
}

func TestPHPShieldInstallRegistersCageFSWithoutMounting(t *testing.T) {
	for _, op := range Operations() {
		if op.ID != "integrate.php_shield" {
			continue
		}
		// ensurePHPShieldCageFSMount edits cagefs.mp and leaves the remount
		// to the operator; installing the hook needs no mount capability.
		if !reflect.DeepEqual(op.Privileges, []Privilege{Root}) {
			t.Errorf("PHP Shield install privileges = %v, want root", op.Privileges)
		}
		if slices.Contains(op.Writes, "cagefs:mounts") {
			t.Error("PHP Shield installer does not mount account cages")
		}
		return
	}
	t.Fatal("PHP Shield installation is missing from the inventory")
}

// These expectations come from the runtime paths named below, not from the
// matrix renderer. They pin claims that internal-consistency checks cannot.
func TestInventoryMatchesRuntimeContracts(t *testing.T) {
	byID := map[string]Op{}
	for _, op := range Operations() {
		byID[op.ID] = op
	}
	for _, tc := range []struct {
		id, source, key, value string
		privileges             []Privilege
		writes                 []string
	}{
		{"detect.process_exec", "daemon/exec_bpf.go: tracepoint load and attach", "detection.exec_monitor_backend", "none", []Privilege{"CAP_BPF", "CAP_PERFMON"}, []string{"kernel:BPF programs and maps"}},
		{"detect.outbound_connections", "daemon/connection_bpf.go: cgroup socket load and attach", "detection.connection_tracker_backend", "none", []Privilege{"CAP_BPF", "CAP_NET_ADMIN"}, []string{"kernel:BPF programs and maps"}},
		{"detect.sensitive_file_writes", "daemon/sensitive_file_bpf.go: LSM load", "detection.sensitive_files_backend", "none", []Privilege{"CAP_BPF", "CAP_PERFMON"}, []string{"kernel:BPF programs and maps"}},
		{"detect.af_alg_sockets", "daemon/af_alg_bpf.go: LSM program denies sockets", "detection.af_alg_backend", "none", []Privilege{"CAP_BPF", "CAP_PERFMON"}, []string{"kernel:AF_ALG socket denial"}},
		{"detect.kernel_oom", "checks/performance.go: CheckSwapAndOOM reads dmesg", "", "", []Privilege{"CAP_SYSLOG"}, nil},
		{"detect.bpf_probe", "health/capabilities.go: probe loads and attaches even when monitors are disabled", "", "", []Privilege{"CAP_BPF", "CAP_PERFMON", "CAP_NET_ADMIN"}, nil},
		{"detect.kernel_livepatch_probe", "daemon/daemon.go: startup kernel probe is unconditional", "", "", []Privilege{Root}, []string{"/var/cache/kcare"}},
		{"detect.scan_account_files", "daemon/fanotify.go: disabled_checks does not stop realtime scans", "", "", []Privilege{Root}, nil},
		{"detect.account_databases", "checks/dbscan.go: db_object_scanning does not stop content scans", "", "", []Privilege{Root}, nil},
		{"state.update_signatures", "daemon/daemon.go: signatureUpdater tests UpdateURL", "signatures.update_url", "\"\"", []Privilege{Root}, []string{"/opt/csm/rules"}},
		{"state.update_forge", "daemon/daemon.go: signatureUpdater separately tests YaraForge.Enabled", "signatures.yara_forge.enabled", "false", []Privilege{Root}, []string{"/opt/csm/rules"}},
		{"respond.clean_file", "checks/autoresponse.go: AutoQuarantineFiles also cleans PHP", "auto_response.enabled", "false", []Privilege{Root}, []string{"/home", "/tmp", "/var/tmp", "/dev/shm", "/opt/csm/quarantine"}},
		{"respond.af_alg_kill", "daemon/af_alg_react.go: separate CopyFailKillProcess gate", "auto_response.copy_fail_kill_process", "false", []Privilege{CapKill}, []string{"process:signal"}},
		{"respond.af_alg_marker", "checks/af_alg_enforce.go: repairs marker inside daemon sandbox", "auto_response.disable_enforce_af_alg", "true", []Privilege{Root}, []string{"/etc/modprobe.d"}},
		{"respond.forward_guard", "daemon/forward_guard.go: disabled guard still removes configuration", "mode", "observe", []Privilege{Root}, []string{"/etc/exim.conf.local", "/var/lib/csm"}},
		{"respond.bpf_deny_egress", "daemon/connection_bpf.go: cgroup socket program", "bpf_enforcement.enabled", "false", []Privilege{"CAP_BPF", "CAP_NET_ADMIN"}, nil},
		{"respond.mail_delivery_gate", "daemon/spoolwatch.go: FAN_DENY on scanner failure in tempfail mode", "email_av.enabled", "false", []Privilege{CapSysAdmin}, []string{"fanotify:mail delivery decisions"}},
		{"respond.hold_outgoing_mail", "daemon/watcher.go: maybeHoldOutgoingMail calls whmapi1 hold_outgoing_email", "auto_response.enabled", "false", []Privilege{Root}, []string{"cpanel:account outgoing mail hold"}},
		{"integrate.challenge_port_gate", "daemon/daemon.go: attachChallengePortGate installs a separate nftables table", "challenge.port_gate.enabled", "false", []Privilege{CapNetAdmin}, nil},
		{"state.control_socket", "daemon/control_listener.go: creates root-only command socket", "", "", []Privilege{Root}, []string{"/var/run/csm"}},
		{"operate.rehash", "cmd/csm/main.go: runRehash also updates service, launcher and immutable flag", "", "", []Privilege{"CAP_LINUX_IMMUTABLE", Root}, []string{"/opt/csm", "/etc/csm", "/etc/systemd/system", "/etc/logrotate.d", "/usr/sbin/csm"}},
		{"operate.install_service", "cmd/csm/installer.go: Uninstall removes cron, snippets, challenge maps, PHP Shield and runtime files", "", "", []Privilege{Root}, []string{"/etc/cron.d", "/var/cache/csm", "/opt/cpanel", "/var/run/csm", "/etc/apache2/conf.d", "/etc/apache2/conf-enabled", "/etc/httpd/conf.d", "/etc/nginx/conf.d", "/usr/local/apache/conf", "/usr/local/lsws/conf/templates"}},
		{"operate.export_archives", "cmd/csm/backup.go and forensic.go: write archives, temporary snapshots and checksum sidecars", "", "", []Privilege{Root}, []string{"filesystem:operator-selected archive destinations"}},
		{"operate.restore_backup", "cmd/csm/restore.go: stage and replace config, drop-ins and state", "", "", []Privilege{Root}, []string{"/etc/csm", "/var/lib/csm", "/opt/csm", "/tmp"}},
		{"integrate.challenge_snippet", "integration/webserver/installer.go: Install and Remove reload the web server", "mode", "observe", []Privilege{Root}, []string{"service:web server reload"}},
		{"operate.manual_remediation", "checks/remediate.go: ApplyFix can kill and quarantine, or truncate a user crontab", "", "", []Privilege{CapKill, Root}, []string{"/home", "/tmp", "/var/tmp", "/dev/shm", "/var/spool/cron", "/var/spool/exim/input", "/var/spool/exim4/input"}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			op, ok := byID[tc.id]
			if !ok {
				t.Fatalf("missing operation: %s", tc.source)
			}
			if op.DisableKey != tc.key || op.DisableValue != tc.value {
				t.Errorf("%s: off = %q: %q, want %q: %q", tc.source, op.DisableKey, op.DisableValue, tc.key, tc.value)
			}
			for _, p := range tc.privileges {
				if !slices.Contains(op.Privileges, p) {
					t.Errorf("%s requires %s", tc.source, p)
				}
			}
			for _, w := range tc.writes {
				if !slices.Contains(op.Writes, w) {
					t.Errorf("%s writes %s", tc.source, w)
				}
			}
		})
	}
}

func TestOperationIDsAreUniqueAndNamespaced(t *testing.T) {
	seen := map[string]bool{}
	for _, op := range Operations() {
		if op.ID == "" {
			t.Fatalf("operation with empty ID: %+v", op)
		}
		if seen[op.ID] {
			t.Errorf("duplicate operation ID %q", op.ID)
		}
		seen[op.ID] = true
		if !strings.Contains(op.ID, ".") {
			t.Errorf("operation ID %q is not namespaced as <subsystem>.<action>", op.ID)
		}
		if op.Subsystem == "" || op.Summary == "" || op.WithoutPrivilege == "" {
			t.Errorf("operation %q leaves a required column empty", op.ID)
		}
		if len(op.Privileges) == 0 {
			t.Errorf("operation %q declares no privilege", op.ID)
		}
		if op.Trigger != Automatic && op.Trigger != Operator {
			t.Errorf("operation %q has trigger %q, want automatic or operator", op.ID, op.Trigger)
		}
	}
	if len(seen) == 0 {
		t.Fatal("inventory is empty")
	}
}

func TestPrivilegesAreKnownValues(t *testing.T) {
	known := map[Privilege]bool{}
	for _, p := range KnownPrivileges() {
		known[p] = true
	}
	for _, op := range Operations() {
		for _, p := range op.Privileges {
			if !known[p] {
				t.Errorf("operation %q declares unknown privilege %q", op.ID, p)
			}
		}
	}
}

// A missing switch must be disclosed, not replaced by an unrelated key.
func TestEveryAutomaticHostChangeExplainsItsControl(t *testing.T) {
	for _, op := range Operations() {
		if op.Trigger != Automatic || !op.ChangesHost() {
			continue
		}
		if op.DisableKey == "" && op.DisableReason == "" {
			t.Errorf("operation %q has no disable key or explanation of why it cannot be disabled", op.ID)
		}
		if op.DisableKey != "" && op.DisableValue == "" {
			t.Errorf("operation %q names %q but not the value to set", op.ID, op.DisableKey)
		}
	}
}

func TestDisableValuesAreValidConfigYAML(t *testing.T) {
	for _, op := range Operations() {
		if op.DisableKey == "" {
			continue
		}
		keys := strings.Split(op.DisableKey, ".")
		doc := "{"
		for i, key := range keys {
			if i > 0 {
				doc += "{"
			}
			doc += key + ": "
		}
		doc += op.DisableValue + strings.Repeat("}", len(keys))
		var cfg config.Config
		decoder := yaml.NewDecoder(strings.NewReader(doc))
		decoder.KnownFields(true)
		if err := decoder.Decode(&cfg); err != nil {
			t.Errorf("%s: disable instruction is not valid config YAML: %v", op.ID, err)
		}
	}
}

func TestUnconfigurableHostChangesAreExplicit(t *testing.T) {
	var ids []string
	for _, op := range Operations() {
		if op.DisableKey != "" && op.DisableReason != "" {
			t.Errorf("%s claims both a switch and no switch", op.ID)
		}
		if op.Trigger == Automatic && op.ChangesHost() && op.DisableKey == "" {
			ids = append(ids, op.ID)
			if !strings.Contains(Markdown(), op.DisableInstruction()) {
				t.Errorf("%s omits its control limitation from the docs", op.ID)
			}
		}
	}
	if want := []string{"detect.bpf_probe", "detect.kernel_livepatch_probe"}; !reflect.DeepEqual(ids, want) {
		t.Errorf("unconfigurable host changes = %v, want %v; verify each new exception against its callers", ids, want)
	}
}

func TestUnprivilegedOperationsDoNotChangeTheHost(t *testing.T) {
	for _, op := range Operations() {
		if len(op.Privileges) == 1 && op.Privileges[0] == Unprivileged && op.ChangesHost() {
			t.Errorf("operation %q changes host state but claims no privilege", op.ID)
		}
	}
}

func TestChangesHostIgnoresCSMOwnedTrees(t *testing.T) {
	own := Op{Writes: []string{"/var/lib/csm", "/opt/csm/quarantine", "/var/log/csm/audit.jsonl"}}
	if own.ChangesHost() {
		t.Error("writes confined to CSM's own trees count as a host change")
	}
	foreign := Op{Writes: []string{"/var/lib/csm", "/home"}}
	if !foreign.ChangesHost() {
		t.Error("a write under /home does not count as a host change")
	}
	resource := Op{Writes: []string{"nftables:csm sets"}}
	if !resource.ChangesHost() {
		t.Error("a non-filesystem resource does not count as a host change")
	}
	traversal := Op{Writes: []string{"/opt/csm/../../etc/shadow"}}
	if !traversal.ChangesHost() {
		t.Error("a path escaping a CSM-owned tree does not count as a host change")
	}
}

// Every DisableKey has to resolve against the real config struct, so a renamed
// YAML key breaks the build instead of leaving the matrix pointing operators
// at a setting that no longer exists.
func TestDisableKeysResolveAgainstConfig(t *testing.T) {
	for _, op := range Operations() {
		if op.DisableKey == "" {
			continue
		}
		if !yamlPathExists(reflect.TypeOf(config.Config{}), strings.Split(op.DisableKey, ".")) {
			t.Errorf("operation %q names config key %q, which does not exist", op.ID, op.DisableKey)
		}
	}
}

func TestNonPathResourcesUseAScheme(t *testing.T) {
	for _, op := range Operations() {
		for _, w := range op.Writes {
			if strings.HasPrefix(w, "/") {
				continue
			}
			if !strings.Contains(w, ":") {
				t.Errorf("operation %q writes %q: non-path resources must be written as <kind>:<name>", op.ID, w)
			}
		}
	}
}

func TestMarkdownRendersEveryOperation(t *testing.T) {
	md := Markdown()
	for _, op := range Operations() {
		if !strings.Contains(md, op.ID) {
			t.Errorf("rendered matrix omits operation %q", op.ID)
		}
	}
	if strings.Contains(md, "|  |") {
		t.Error("rendered matrix has an empty cell")
	}
}

func TestOperationsAreOrderedForReading(t *testing.T) {
	ops := Operations()
	for i := 1; i < len(ops); i++ {
		prev, cur := ops[i-1], ops[i]
		if prev.Subsystem > cur.Subsystem {
			t.Fatalf("subsystems out of order: %q before %q", prev.Subsystem, cur.Subsystem)
		}
		if prev.Subsystem == cur.Subsystem && prev.ID > cur.ID {
			t.Fatalf("IDs out of order inside %q: %q before %q", cur.Subsystem, prev.ID, cur.ID)
		}
	}
}

// yamlPathExists walks a dotted YAML path through a struct type, following the
// same `yaml:"..."` tags the loader uses.
func yamlPathExists(t reflect.Type, path []string) bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if len(path) == 0 {
		return true
	}
	if t.Kind() != reflect.Struct {
		return false
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if name != path[0] {
			continue
		}
		return yamlPathExists(f.Type, path[1:])
	}
	return false
}

// The audited set is pinned so the column cannot drift optimistically: adding
// an operation to it means wiring the action record and updating this list in
// the same change.
func TestAuditedOperationsArePinned(t *testing.T) {
	var audited []string
	for _, op := range Operations() {
		if op.Audited {
			audited = append(audited, op.ID)
		}
	}
	want := []string{
		"integrate.firewall_ruleset",
		"operate.manual_firewall",
		"respond.block_ip",
		"respond.clean_file",
		"respond.kill_process",
		"respond.quarantine_file",
	}
	if !reflect.DeepEqual(audited, want) {
		t.Errorf("audited operations = %v, want %v; wire the action record before claiming coverage", audited, want)
	}
}

func TestMarkdownReportsAuditCoverage(t *testing.T) {
	md := Markdown()
	if !strings.Contains(md, "Action record") {
		t.Fatal("rendered matrix has no audit-coverage column")
	}
	for _, op := range Operations() {
		if !op.Audited {
			continue
		}
		for _, line := range strings.Split(md, "\n") {
			if strings.Contains(line, "`"+op.ID+"`") && !strings.Contains(line, "| yes |") {
				t.Errorf("row for %q does not report its action record", op.ID)
			}
		}
	}
}

func TestEveryOperationHasARiskTier(t *testing.T) {
	for _, op := range Operations() {
		if op.Risk.Number() < 0 || op.Risk > RiskDestructive {
			t.Errorf("%s has no risk tier (Risk=%d)", op.ID, op.Risk)
		}
	}
}

// Tier 0 means nothing outside CSM's own trees changes. A host change in tier
// 0, or a tier above 0 that changes nothing, is a misclassification.
func TestRiskTierZeroIsExactlyNoHostChange(t *testing.T) {
	for _, op := range Operations() {
		if (op.Risk == RiskObserve) == op.ChangesHost() {
			t.Errorf("%s: Risk tier %d but ChangesHost()=%v", op.ID, op.Risk.Number(), op.ChangesHost())
		}
	}
}

// The firewall and file slice of the auto-response safety model owns these
// operations and states their contract. Adding a contract elsewhere means the
// operation's slice has specified its authority, identity revalidation,
// recovery and limit; update this list in the same change.
func TestSafetyContractsArePinnedAndComplete(t *testing.T) {
	var got []string
	for _, op := range Operations() {
		if op.Contract == nil {
			continue
		}
		got = append(got, op.ID)
		c := op.Contract
		for field, v := range map[string]string{"Authority": c.Authority, "Identity": c.Identity, "Recovery": c.Recovery, "Limit": c.Limit} {
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s contract has an empty %s", op.ID, field)
			}
		}
		if op.Risk.Number() < 2 {
			t.Errorf("%s has a contract but tier %d; contracts describe host changes", op.ID, op.Risk.Number())
		}
	}
	want := []string{
		"integrate.challenge_port_gate",
		"integrate.challenge_snippet",
		"integrate.firewall_ruleset",
		"operate.manual_firewall",
		"respond.block_ip",
		"respond.clean_file",
		"respond.quarantine_file",
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("operations with a safety contract = %v, want %v", got, want)
	}
}

func TestRiskTierNumbers(t *testing.T) {
	for tier, want := range map[RiskTier]int{RiskUnclassified: -1, RiskObserve: 0, RiskPreview: 1, RiskReversible: 2, RiskContain: 3, RiskDestructive: 4, RiskTier(255): -1} {
		if got := tier.Number(); got != want {
			t.Errorf("RiskTier(%d).Number() = %d, want %d", tier, got, want)
		}
	}
}

// reviewedRiskTiers is the independent oracle for the inventory's tiers. A
// ChangesHost check alone would accept swapping tier 2 and tier 4.
var reviewedRiskTiers = map[string]RiskTier{
	"detect.account_databases":      RiskObserve,
	"detect.af_alg_sockets":         RiskContain,
	"detect.audit_rules":            RiskObserve,
	"detect.bpf_probe":              RiskReversible,
	"detect.filesystem_events":      RiskObserve,
	"detect.kernel_livepatch_probe": RiskReversible,
	"detect.kernel_oom":             RiskObserve,
	"detect.mail_queue_probe":       RiskReversible,
	"detect.outbound_connections":   RiskReversible,
	"detect.pam_events":             RiskObserve,
	"detect.process_exec":           RiskReversible,
	"detect.read_service_logs":      RiskObserve,
	"detect.scan_account_files":     RiskObserve,
	"detect.sensitive_file_writes":  RiskReversible,
	"integrate.auditd_rules":        RiskDestructive,
	"integrate.challenge_port_gate": RiskReversible,
	"integrate.challenge_snippet":   RiskDestructive,
	"integrate.firewall_ruleset":    RiskDestructive,
	"integrate.modsec_section":      RiskDestructive,
	"integrate.panel_plugin":        RiskDestructive,
	"integrate.php_shield":          RiskDestructive,
	"integrate.waf_vendor_rules":    RiskDestructive,
	"operate.export_archives":       RiskDestructive,
	"operate.harden_host":           RiskDestructive,
	"operate.install_service":       RiskDestructive,
	"operate.manual_firewall":       RiskContain,
	"operate.manual_remediation":    RiskDestructive,
	"operate.rehash":                RiskDestructive,
	"operate.restore_backup":        RiskDestructive,
	"operate.truncate_error_log":    RiskDestructive,
	"respond.af_alg_enforce":        RiskDestructive,
	"respond.af_alg_kill":           RiskDestructive,
	"respond.af_alg_marker":         RiskDestructive,
	"respond.block_ip":              RiskContain,
	"respond.bpf_deny_egress":       RiskContain,
	"respond.clean_file":            RiskDestructive,
	"respond.database_cleanup":      RiskDestructive,
	"respond.enforce_permissions":   RiskContain,
	"respond.fix_wp_cron":           RiskDestructive,
	"respond.forward_guard":         RiskDestructive,
	"respond.forward_guard_lookup":  RiskObserve,
	"respond.freeze_mail":           RiskReversible,
	"respond.hold_outgoing_mail":    RiskReversible,
	"respond.kill_process":          RiskDestructive,
	"respond.mail_delivery_gate":    RiskReversible,
	"respond.quarantine_file":       RiskContain,
	"respond.quarantine_mail":       RiskContain,
	"respond.restart_mail_auth":     RiskDestructive,
	"respond.virtual_patch":         RiskContain,
	"state.control_socket":          RiskObserve,
	"state.mail_relay_policies":     RiskObserve,
	"state.php_shield_events":       RiskObserve,
	"state.sign_config":             RiskObserve,
	"state.update_forge":            RiskObserve,
	"state.update_signatures":       RiskObserve,
	"state.write_deploy_script":     RiskObserve,
	"state.write_logs":              RiskObserve,
	"state.write_store":             RiskObserve,
}

func TestRiskTiersMatchReviewedInventory(t *testing.T) {
	seen := map[string]bool{}
	for _, op := range Operations() {
		if seen[op.ID] {
			t.Errorf("duplicate operation %s", op.ID)
		}
		seen[op.ID] = true
		want, ok := reviewedRiskTiers[op.ID]
		if !ok {
			t.Errorf("%s is missing from the reviewed tier table", op.ID)
			continue
		}
		if op.Risk != want {
			t.Errorf("%s: Risk tier %d, reviewed %d", op.ID, op.Risk.Number(), want.Number())
		}
	}
	for id := range reviewedRiskTiers {
		if !seen[id] {
			t.Errorf("reviewed tier table lists %s, which is not an operation", id)
		}
	}
	for id, want := range map[string]RiskTier{"operate.export_archives": RiskDestructive, "respond.virtual_patch": RiskContain} {
		if reviewedRiskTiers[id] != want {
			t.Errorf("%s must stay tier %d", id, want.Number())
		}
	}
}

// reviewedRecoveryGaps pins the host-changing operations whose recovery this
// inventory does not yet cover, with the exact gap each one states.
var reviewedRecoveryGaps = map[string]string{
	"detect.af_alg_sockets":         "This inventory does not yet specify verified detach, map restoration and crash recovery for these kernel hooks.",
	"detect.bpf_probe":              "This inventory does not yet specify verified detach, map restoration and crash recovery for these kernel hooks.",
	"detect.kernel_livepatch_probe": "This inventory does not specify recovery of incidental external cache or log writes by probe commands.",
	"detect.mail_queue_probe":       "This inventory does not specify recovery of incidental external cache or log writes by probe commands.",
	"detect.outbound_connections":   "This inventory does not yet specify verified detach, map restoration and crash recovery for these kernel hooks.",
	"detect.process_exec":           "This inventory does not yet specify verified detach, map restoration and crash recovery for these kernel hooks.",
	"detect.sensitive_file_writes":  "This inventory does not yet specify verified detach, map restoration and crash recovery for these kernel hooks.",
	"integrate.auditd_rules":        "This inventory does not specify an action-wide snapshot and verified rollback of configuration, service and external-tool side effects.",
	"integrate.modsec_section":      "This inventory does not specify an action-wide snapshot and verified rollback of configuration, service and external-tool side effects.",
	"integrate.panel_plugin":        "This inventory does not specify an action-wide snapshot and verified rollback of configuration, service and external-tool side effects.",
	"integrate.php_shield":          "This inventory does not specify an action-wide snapshot and verified rollback of configuration, service and external-tool side effects.",
	"integrate.waf_vendor_rules":    "This inventory does not specify an action-wide snapshot and verified rollback of configuration, service and external-tool side effects.",
	"operate.export_archives":       "Export can replace an existing operator-selected archive; removing the new archive does not restore overwritten bytes.",
	"operate.harden_host":           "This inventory does not specify an action-wide snapshot and verified rollback of configuration, service and external-tool side effects.",
	"operate.install_service":       "This inventory does not specify an action-wide snapshot and verified rollback of configuration, service and external-tool side effects.",
	"operate.manual_remediation":    "Current remediation may retain local recovery evidence, but per-operation identity-checked undo and partial-failure recovery are not specified by this inventory.",
	"operate.rehash":                "This inventory does not specify an action-wide snapshot and verified rollback of configuration, service and external-tool side effects.",
	"operate.restore_backup":        "This inventory does not specify an action-wide snapshot and verified rollback of configuration, service and external-tool side effects.",
	"operate.truncate_error_log":    "Current remediation may retain local recovery evidence, but per-operation identity-checked undo and partial-failure recovery are not specified by this inventory.",
	"respond.af_alg_enforce":        "This inventory does not specify an action-wide snapshot and verified rollback of configuration, service and external-tool side effects.",
	"respond.af_alg_kill":           "Process termination and restart cannot restore lost process state; this inventory does not yet specify a full recovery contract.",
	"respond.af_alg_marker":         "This inventory does not specify an action-wide snapshot and verified rollback of configuration, service and external-tool side effects.",
	"respond.bpf_deny_egress":       "This inventory does not yet specify verified detach, map restoration and crash recovery for these kernel hooks.",
	"respond.database_cleanup":      "Current remediation may retain local recovery evidence, but per-operation identity-checked undo and partial-failure recovery are not specified by this inventory.",
	"respond.enforce_permissions":   "Current remediation may retain local recovery evidence, but per-operation identity-checked undo and partial-failure recovery are not specified by this inventory.",
	"respond.fix_wp_cron":           "This inventory does not specify an action-wide snapshot and verified rollback of configuration, service and external-tool side effects.",
	"respond.forward_guard":         "This inventory does not specify an action-wide snapshot and verified rollback of configuration, service and external-tool side effects.",
	"respond.freeze_mail":           "This inventory does not yet specify identity checks for releasing or restoring mail, or recovery after a restart.",
	"respond.hold_outgoing_mail":    "This inventory does not yet specify identity checks for releasing or restoring mail, or recovery after a restart.",
	"respond.kill_process":          "Process termination and restart cannot restore lost process state; this inventory does not yet specify a full recovery contract.",
	"respond.mail_delivery_gate":    "This inventory does not yet specify identity checks for releasing or restoring mail, or recovery after a restart.",
	"respond.quarantine_mail":       "This inventory does not yet specify identity checks for releasing or restoring mail, or recovery after a restart.",
	"respond.restart_mail_auth":     "Process termination and restart cannot restore lost process state; this inventory does not yet specify a full recovery contract.",
	"respond.virtual_patch":         "Current remediation may retain local recovery evidence, but per-operation identity-checked undo and partial-failure recovery are not specified by this inventory.",
}

func TestHostChangesDeclareRecoveryCoverage(t *testing.T) {
	got := map[string]string{}
	for _, op := range Operations() {
		hasContract := op.Contract != nil
		hasGap := strings.TrimSpace(op.RecoveryGap) != ""
		switch {
		case !op.ChangesHost() && hasGap:
			t.Errorf("%s changes nothing on the host but declares a recovery gap", op.ID)
		case op.ChangesHost() && hasContract == hasGap:
			t.Errorf("%s changes the host and must declare exactly one of a contract or a recovery gap (contract=%v gap=%v)", op.ID, hasContract, hasGap)
		}
		if hasGap {
			if _, dup := got[op.ID]; dup {
				t.Errorf("duplicate recovery gap for %s", op.ID)
			}
			got[op.ID] = op.RecoveryGap
		}
	}
	if !reflect.DeepEqual(got, reviewedRecoveryGaps) {
		for id, gap := range reviewedRecoveryGaps {
			if got[id] != gap {
				t.Errorf("%s recovery gap = %q, reviewed %q", id, got[id], gap)
			}
		}
		for id := range got {
			if _, ok := reviewedRecoveryGaps[id]; !ok {
				t.Errorf("%s declares a recovery gap that is not in the reviewed list", id)
			}
		}
	}
	data, err := os.ReadFile("../../docs/src/capability-matrix.md")
	if err != nil {
		t.Fatalf("read capability matrix doc: %v", err)
	}
	doc := string(data)
	if end := strings.Index(doc, "<!-- END GENERATED MATRIX -->"); end >= 0 {
		doc = doc[end:]
	} else {
		t.Fatal("capability matrix doc has no generated block end marker")
	}
	var rows []string
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "|") {
			rows = append(rows, line)
		}
	}
	for id, gap := range reviewedRecoveryGaps {
		found := false
		for _, row := range rows {
			if strings.Contains(row, "`"+id+"`") && strings.Contains(row, gap) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("capability matrix doc has no recovery-gap row naming %s with its gap text", id)
		}
	}
}

func TestOperationsJSONReportsRiskTier(t *testing.T) {
	ops := Operations()
	raw, err := json.Marshal(ops)
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		ID          string
		Risk        *int
		Contract    *SafetyContract
		RecoveryGap string
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(ops) {
		t.Fatalf("JSON rows = %d, want %d", len(rows), len(ops))
	}
	for i, row := range rows {
		op := ops[i]
		if row.ID != op.ID {
			t.Fatalf("JSON row %d is %q, want %q", i, row.ID, op.ID)
		}
		if row.Risk == nil {
			t.Errorf("%s JSON has no risk", op.ID)
		} else if *row.Risk != op.Risk.Number() {
			t.Errorf("%s JSON risk = %d, want %d", op.ID, *row.Risk, op.Risk.Number())
		}
		if !reflect.DeepEqual(row.Contract, op.Contract) || row.RecoveryGap != op.RecoveryGap {
			t.Errorf("%s JSON contract or gap differs from the inventory", op.ID)
		}
	}
	for tier, want := range map[RiskTier]string{RiskUnclassified: "-1", RiskObserve: "0", RiskPreview: "1", RiskReversible: "2", RiskContain: "3", RiskDestructive: "4", RiskTier(255): "-1"} {
		got, err := json.Marshal(tier)
		if err != nil || string(got) != want {
			t.Errorf("json(RiskTier(%d)) = %s, %v; want %s", tier, got, err, want)
		}
	}
}

func TestOperationsJSONRoundTrip(t *testing.T) {
	want := Operations()
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got []Op
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("decoding the inventory changed its operation metadata")
	}
}

func TestRiskTierUnmarshalJSON(t *testing.T) {
	for raw, want := range map[string]RiskTier{
		"-1": RiskUnclassified,
		"0":  RiskObserve,
		"1":  RiskPreview,
		"2":  RiskReversible,
		"3":  RiskContain,
		"4":  RiskDestructive,
	} {
		t.Run(raw, func(t *testing.T) {
			var got RiskTier
			if err := json.Unmarshal([]byte(raw), &got); err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("decoded tier = %v, want %v", got, want)
			}
		})
	}
	for _, raw := range []string{"-2", "5", "255", "256", "1.5", `"2"`, "true", "{}", "[]"} {
		t.Run(raw, func(t *testing.T) {
			got := RiskDestructive
			if err := json.Unmarshal([]byte(raw), &got); err == nil {
				t.Fatal("accepted an invalid risk tier")
			}
			if got != RiskDestructive {
				t.Fatal("invalid input changed the previous risk tier")
			}
		})
	}
	// Like other scalar JSON destinations, null leaves an existing value intact.
	got := RiskContain
	if err := json.Unmarshal([]byte("null"), &got); err != nil || got != RiskContain {
		t.Fatalf("null changed the risk tier: got %v, err %v", got, err)
	}
}

func TestOperationsCopiesSafetyContracts(t *testing.T) {
	var first *SafetyContract
	for _, op := range Operations() {
		if op.ID == "respond.block_ip" {
			first = op.Contract
		}
	}
	if first == nil {
		t.Fatal("respond.block_ip has no contract")
	}
	saved := *first
	t.Cleanup(func() { *first = saved })
	first.Authority, first.Identity, first.Recovery, first.Limit = "x", "x", "x", "x"
	for _, op := range Operations() {
		if op.ID != "respond.block_ip" {
			continue
		}
		if op.Contract == first {
			t.Fatal("Operations returns the shared contract pointer")
		}
		if *op.Contract != saved {
			t.Errorf("a caller changed the shared contract: %+v", *op.Contract)
		}
	}
}

func TestMarkdownReportsRiskTier(t *testing.T) {
	md := Markdown()
	header := "| Operation | Needs | Trigger | Risk tier | Writes | Turn it off | Action record | Without the privilege |"
	if strings.SplitN(md, "\n", 2)[0] != header {
		t.Fatal("rendered matrix has no correctly placed risk tier column")
	}
	rows := 0
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "| `") {
			rows++
		}
	}
	ops := Operations()
	if rows != len(ops) {
		t.Fatalf("rows=%d want %d", rows, len(ops))
	}
	for _, op := range ops {
		count := 0
		for _, line := range strings.Split(md, "\n") {
			if !strings.HasPrefix(line, fmt.Sprintf("| `%s`<br>", op.ID)) {
				continue
			}
			count++
			cells := strings.Split(line, "|")
			if len(cells) != 10 {
				t.Fatalf("%s: expected eight cells: %q", op.ID, line)
			}
			if strings.TrimSpace(cells[3]) != string(op.Trigger) || strings.TrimSpace(cells[4]) != strconv.Itoa(op.Risk.Number()) {
				t.Errorf("%s: wrong trigger/tier cells: %q", op.ID, line)
			}
		}
		if count != 1 {
			t.Errorf("%s: row count=%d want 1", op.ID, count)
		}
	}
}

// The block_ip contract is public. It must state which automatic block paths
// the check registry and the hourly budget govern, so an uncharged subnet
// path cannot hide behind a general claim.
func TestBlockIPContractStatesRegistryAndBudgetScope(t *testing.T) {
	var c *SafetyContract
	for _, op := range Operations() {
		if op.ID == "respond.block_ip" {
			c = op.Contract
		}
	}
	if c == nil {
		t.Fatal("respond.block_ip has no contract")
	}
	wantAuthority := "single-IP scan blocks require a check the registry marks blockable, auto_response.enabled and block_ips, and non-observe mode; the subnet-spray, ASN-crawl and netblock escalation paths block subnets under their own fixed rules without consulting the registry; other automatic callers retain their own gates; the wired engine dry_run callback suppresses live automatic blocks"
	wantLimit := "max_blocks_per_hour charges single-IP scan blocks and ASN-crawl subnets only; subnet-spray and netblock escalation subnets, and challenge-timeout, incident, spray and central-intel blocks, are not charged; single-IP deny limits do not provide an all-source or subnet ceiling"
	if c.Authority != wantAuthority {
		t.Errorf("block_ip Authority = %q\nwant %q", c.Authority, wantAuthority)
	}
	if c.Limit != wantLimit {
		t.Errorf("block_ip Limit = %q\nwant %q", c.Limit, wantLimit)
	}
}

// reviewedSafetyContracts pins the public contract text. Each field was
// checked against the code it describes; a change to one needs the same
// review, so it must be made here too.
var reviewedSafetyContracts = map[string]SafetyContract{
	"integrate.challenge_port_gate": {
		Authority: "challenge startup with challenge.enabled and challenge.port_gate.enabled; a loopback-only listener or non-Linux build has no gate",
		Identity:  "Allow validates the address and listener family; IPList adds membership before calling Allow after unlocking; the gate itself does not revalidate list membership; loopback and configured infrastructure ranges have accept rules",
		Recovery:  "elements carry kernel timeouts; explicit list removal attempts Revoke, while expiry relies on the kernel timeout; gate errors are logged and list/map/gate changes are not one transaction",
		Limit:     "no challenge-list capacity or generation fence is present; gate installation failure leaves the listener publicly reachable",
	},
	"integrate.challenge_snippet": {
		Authority: "non-observe startup refreshes legacy snippets and stale managed snippets on supported web servers independently of challenge.enabled; explicit integration commands also install or remove them",
		Identity:  "managed Install and Remove run the web server configtest after changing the snippet and before reload; legacy map-reference repair and runtime map updates do not use that transaction",
		Recovery:  "managed configtest or reload failure attempts to restore previous snippet bytes; restore failures are logged and recovery reload is best-effort; legacy repair and runtime maps have no unified rollback with the gate",
		Limit:     "managed Install skips identical bytes, and nginx map reload skips unchanged maps; there is no shared reload pacing or capacity bound",
	},
	"integrate.firewall_ruleset": {
		Authority: "daemon firewall startup or reload when enabled and permitted by mode, or an explicit operator apply",
		Identity:  "Apply holds the engine lock and batches old-table deletion, new rules and persisted set elements into one nftables transaction; the legacy state loader can seed empty elements on missing or malformed state",
		Recovery:  "a rejected kernel batch leaves the prior kernel table; timed snapshot recovery belongs to apply-confirmed, not every Apply; kernel atomicity is not an atomic transaction with disk state",
		Limit:     "one Apply per engine lock; this is ruleset installation, not automatic block admission",
	},
	"operate.manual_firewall": {
		Authority: "an operator command accepted by the root control socket or an admin-authorized web UI request",
		Identity:  "single-IP force blocks retain canonicalization and hard address guards under the engine lock but bypass automatic dry-run and soft allows; subnet blocks still refuse protected overlap",
		Recovery:  "unblock and remove-allow reverse their selected entries; apply-confirmed has a timed ruleset snapshot rollback; a flush has no general inverse that restores all prior entries",
		Limit:     "single-IP deny limits still apply; manual commands bypass the automatic hourly budget and have no shared all-operation ceiling",
	},
	"respond.block_ip": {
		Authority: "single-IP scan blocks require a check the registry marks blockable, auto_response.enabled and block_ips, and non-observe mode; the subnet-spray, ASN-crawl and netblock escalation paths block subnets under their own fixed rules without consulting the registry; other automatic callers retain their own gates; the wired engine dry_run callback suppresses live automatic blocks",
		Identity:  "single-IP targets are canonicalized; infrastructure, local, loopback, unspecified, link-local and operator-allow checks run under the engine lock; verified-range callbacks run outside that lock; subnet paths check protected overlap; the engine does not authenticate registry evidence",
		Recovery:  "temporary single-IP elements expire in the kernel; temporary subnet expiry requires daemon cleanup because subnet sets have no kernel timeouts; unblock or blocked-IP flush removes IP entries, while subnets require subnet removal; permanent entries do not expire and inverse operations do not reconstruct evicted entries or lost traffic",
		Limit:     "max_blocks_per_hour charges single-IP scan blocks and ASN-crawl subnets only; subnet-spray and netblock escalation subnets, and challenge-timeout, incident, spray and central-intel blocks, are not charged; single-IP deny limits do not provide an all-source or subnet ceiling",
	},
	"respond.clean_file": {
		Authority: "automatic cleaning requires auto_response.enabled and non-observe mode; PHP cleaning is the supported batch quarantine alternative and also requires quarantine_files; access-file cleaning instead requires clean_htaccess",
		Identity:  "the automatic caller's captured device/inode, size and modification time are checked after reservation and against the opened descriptor; the cleaner revalidates the target before replacement",
		Recovery:  "a durable pre-clean backup carries saved attributes before replacement; pre-replacement failure leaves the source, but a later directory-sync failure can report failure after cleaned bytes were installed; failed cleaning does not escalate to quarantine",
		Limit:     "the same persisted host/account attempt limits and host-wide failure pause as quarantine; dry_run does not preview cleaning",
	},
	"respond.quarantine_file": {
		Authority: "automatic quarantine requires auto_response.enabled, quarantine_files and non-observe mode; the batch path selects eligible Critical findings and realtime signatures pass the high-confidence validator; directories and special files are refused by the automatic gate",
		Identity:  "device/inode plus size and modification time are captured before reservation and rechecked after it and when opening the source; quarantine copies from the verified descriptor and checks again before removal; these stat checks are not a content hash",
		Recovery:  "successful quarantine retains a recovery copy and owner, permissions and modification time for restore; failures can retain a copy or occur after source removal, so inspect action evidence before retrying",
		Limit:     "shared persisted rolling-hour host and account attempt limits and a host-wide failure pause; failed and interrupted attempts remain charged; dry_run does not preview file actions",
	},
}

func TestSafetyContractsMatchReviewedText(t *testing.T) {
	seen := map[string]bool{}
	for _, op := range Operations() {
		if op.Contract == nil {
			continue
		}
		seen[op.ID] = true
		want, ok := reviewedSafetyContracts[op.ID]
		if !ok {
			t.Errorf("%s has a contract that is not in the reviewed list", op.ID)
			continue
		}
		if *op.Contract != want {
			t.Errorf("%s contract = %+v\nreviewed %+v", op.ID, *op.Contract, want)
		}
	}
	for id := range reviewedSafetyContracts {
		if !seen[id] {
			t.Errorf("reviewed contract for %s has no matching operation contract", id)
		}
	}
}
