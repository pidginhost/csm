package privops

import (
	"reflect"
	"slices"
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
