package checks

import (
	"sort"
	"strings"
	"sync"
	"testing"
)

// legacyEligibleBaseline is the 22-key securityEventChecks table at the
// baseline commit minus php_dropper (never emitted by any version) and the
// two host-scope names. It is test data; it must never be generated from
// the registry.
var legacyEligibleBaseline = []string{
	"fake_kernel_thread", "suspicious_process", "php_suspicious_execution",
	"backdoor_binary", "webshell", "new_webshell_file", "new_executable_in_config",
	"new_php_in_uploads", "new_php_in_languages", "new_php_in_upgrade",
	"obfuscated_php", "webshell_realtime", "php_in_uploads_realtime",
	"php_in_sensitive_dir_realtime", "executable_in_config_realtime",
	"obfuscated_php_realtime", "webshell_content_realtime", "c2_connection",
	"cpanel_file_upload_realtime",
}

func TestEveryCheckIsClassified(t *testing.T) {
	if err := validateCorrelationPolicy(checkRegistry); err != nil {
		t.Fatal(err)
	}
	for _, c := range checkRegistry {
		if c.Correlation == CorrelationUnclassified {
			t.Errorf("%s: unclassified; set Correlation in registry.go", c.Name)
		}
	}
}

func namesWithClass(class CorrelationClass) []string {
	var out []string
	for _, c := range checkRegistry {
		if c.Correlation == class {
			out = append(out, c.Name)
		}
	}
	sort.Strings(out)
	return out
}

func TestMalwareArtifactSetIsPinned(t *testing.T) {
	want := "backdoor_binary,new_executable_in_config,new_webshell_file,webshell"
	if got := strings.Join(namesWithClass(CorrelationMalwareArtifact), ","); got != want {
		t.Fatalf("malware artifact set %q, want %q; widening cross_account_malware is a separate decision", got, want)
	}
}

func TestDerivedSetIsPinned(t *testing.T) {
	if got := strings.Join(namesWithClass(CorrelationDerived), ","); got != "coordinated_attack,cross_account_malware" {
		t.Fatalf("derived set %q", got)
	}
	if got := strings.Join(DerivedCorrelationChecks(), ","); got != "coordinated_attack,cross_account_malware" {
		t.Fatalf("DerivedCorrelationChecks() = %q", got)
	}
	if !IsDerivedCorrelationCheck("coordinated_attack") || !IsDerivedCorrelationCheck("cross_account_malware") {
		t.Fatal("derived names not recognised")
	}
	if IsDerivedCorrelationCheck("webshell") || IsDerivedCorrelationCheck("nope") || IsDerivedCorrelationCheck("") {
		t.Fatal("non-derived names recognised as derived")
	}
	out := DerivedCorrelationChecks()
	out[0] = "mutated"
	if DerivedCorrelationChecks()[0] == "mutated" {
		t.Fatal("DerivedCorrelationChecks() exposes shared memory")
	}
}

func TestLegacyBaselineStaysEligible(t *testing.T) {
	for _, name := range legacyEligibleBaseline {
		if _, ok := LookupCheck(name); !ok {
			t.Errorf("%s is not registered", name)
		}
		if !securityEventEligible(name) {
			t.Errorf("%s was eligible before this change and is no longer", name)
		}
	}
	for _, name := range []string{"shadow_change", "root_password_change"} {
		info, ok := LookupCheck(name)
		if !ok || info.Correlation != CorrelationIgnored || info.CorrelationReason != reasonHostScope {
			t.Errorf("%s must be Ignored with reasonHostScope, got %+v", name, info)
		}
		if securityEventEligible(name) {
			t.Errorf("%s must not be eligible", name)
		}
	}
	if _, ok := LookupCheck("php_dropper"); ok {
		t.Error("php_dropper was never emitted and must not be registered")
	}
}

// Independent positive and negative pins: a test that only compares two
// registry-derived sets cannot detect a wrong assignment.
func TestClassificationExamples(t *testing.T) {
	eligible := []string{
		"db_rogue_admin", "joomla_admin_injection", "drupal_admin_injection",
		"magento_admin_injection", "opencart_admin_injection",
		"db_malicious_event", "db_malicious_function", "db_malicious_procedure", "db_malicious_trigger",
		"suspicious_crontab", "backdoor_port", "backdoor_port_outbound", "bad_asn_outbound", "c2_connection",
		"mail_account_compromised", "phishing_page", "htaccess_injection", "yara_match_scheduled",
		"db_stored_code_execution", "email_php_relay_abuse",
	}
	for _, name := range eligible {
		info, ok := LookupCheck(name)
		if !ok {
			t.Errorf("%s not registered", name)
			continue
		}
		if !securityEventEligible(name) || info.Correlation == CorrelationMalwareArtifact {
			t.Errorf("%s should be a plain security event, got class %d", name, info.Correlation)
		}
	}
	ignored := map[string]string{
		"db_content_scan_incomplete":  reasonSelfHealth,
		"db_spam_cleaned":             reasonResponse,
		"db_siteurl_invalid":          reasonPosture,
		"admin_cross_account_overlap": reasonAccountAggregate,
		"bulk_password_change":        reasonAccountAggregate,
		"shadow_change":               reasonHostScope,
		"root_password_change":        reasonHostScope,
		"email_malware":               reasonAttackerSide,
		"email_phishing_content":      reasonAttackerSide,
		"php_config_change":           reasonPosture,
		"php_config_realtime":         reasonPosture,
		"email_mail_filters":          reasonSelfHealth,
		"database_dump":               reasonInformational,
		"suspicious_file":             reasonHostScope,
		"wp_login_bruteforce":         reasonAttackerSide,
		"ip_reputation":               reasonAttackerSide,
		"perf_load":                   reasonPerformance,
		"kernel_module":               reasonHostScope,
		"cpanel_login":                reasonInformational,
		"auto_block":                  reasonResponse,
		"test_alert":                  reasonInformational,
	}
	for name, reason := range ignored {
		info, ok := LookupCheck(name)
		if !ok {
			t.Errorf("%s not registered", name)
			continue
		}
		if info.Correlation != CorrelationIgnored || info.CorrelationReason != reason {
			t.Errorf("%s: got class %d reason %q, want Ignored/%s", name, info.Correlation, info.CorrelationReason, reason)
		}
		if securityEventEligible(name) {
			t.Errorf("%s must not be eligible", name)
		}
	}
	if securityEventEligible("not_a_check") || securityEventEligible("") {
		t.Error("unknown names are never eligible")
	}
	if securityEventEligible("coordinated_attack") || securityEventEligible("cross_account_malware") {
		t.Error("derived names are never eligible")
	}
}

func TestAttributionGapsArePinned(t *testing.T) {
	gaps := map[string]string{
		"c2_connection":          gapSocketOwner,
		"backdoor_port":          gapSocketOwner,
		"backdoor_port_outbound": gapSocketOwner,
		"bad_asn_outbound":       gapPartialSocketOwner,
	}
	for _, c := range checkRegistry {
		if want := gaps[c.Name]; c.CorrelationGap != want {
			t.Errorf("%s: gap %q, want %q", c.Name, c.CorrelationGap, want)
		}
	}
	for name := range gaps {
		if !securityEventEligible(name) {
			t.Errorf("%s: a documented gap must not remove eligibility", name)
		}
	}
}

func TestValidateCorrelationPolicyRejects(t *testing.T) {
	extended := append(append([]CheckInfo(nil), checkRegistry...), CheckInfo{Name: "zz_new_check", Category: CategoryWeb})
	if err := validateCorrelationPolicy(extended); err == nil || !strings.Contains(err.Error(), "zz_new_check") {
		t.Fatalf("expected diagnostic naming zz_new_check, got %v", err)
	}
	bad := map[string]CheckInfo{
		"free-text reason":   {Name: "a", Category: CategoryWeb, Correlation: CorrelationIgnored, CorrelationReason: "because"},
		"blank reason":       {Name: "b", Category: CategoryWeb, Correlation: CorrelationIgnored},
		"reason on eligible": {Name: "c", Category: CategoryWeb, Correlation: CorrelationSecurityEvent, CorrelationReason: reasonPosture},
		"reason on malware":  {Name: "d", Category: CategoryWeb, Correlation: CorrelationMalwareArtifact, CorrelationReason: reasonPosture},
		"reason on derived":  {Name: "e", Category: CategoryWeb, Correlation: CorrelationDerived, CorrelationReason: reasonPosture},
		"unknown enum":       {Name: "f", Category: CategoryWeb, Correlation: CorrelationClass(99)},
		"gap on ignored":     {Name: "g", Category: CategoryWeb, Correlation: CorrelationIgnored, CorrelationReason: reasonPosture, CorrelationGap: gapSocketOwner},
		"gap on derived":     {Name: "h", Category: CategoryWeb, Correlation: CorrelationDerived, CorrelationGap: gapSocketOwner},
		"unknown gap":        {Name: "i", Category: CategoryWeb, Correlation: CorrelationSecurityEvent, CorrelationGap: "made-up"},
	}
	for name, entry := range bad {
		err := validateCorrelationPolicy([]CheckInfo{entry})
		if err == nil {
			t.Errorf("%s: entry %+v accepted", name, entry)
			continue
		}
		if !strings.Contains(err.Error(), `"`+entry.Name+`"`) {
			t.Errorf("%s: diagnostic %q does not name the check", name, err)
		}
	}
	// A recognised gap on the wrong check, or a missing required gap, is a
	// policy error even though the shape validator accepts it.
	wrong := append([]CheckInfo(nil), checkRegistry...)
	for i := range wrong {
		switch wrong[i].Name {
		case "webshell_realtime":
			wrong[i].CorrelationGap = gapSocketOwner
		case "c2_connection":
			wrong[i].CorrelationGap = ""
		}
	}
	if err := checkRequiredGaps(wrong); err == nil {
		t.Fatal("wrong and missing gaps accepted")
	}
	if err := checkRequiredGaps(checkRegistry); err != nil {
		t.Fatal(err)
	}
}

// checkRequiredGaps is the test-side statement of which checks carry which
// gap; it mirrors TestAttributionGapsArePinned for copied inputs.
func checkRequiredGaps(entries []CheckInfo) error {
	required := map[string]string{
		"c2_connection": gapSocketOwner, "backdoor_port": gapSocketOwner,
		"backdoor_port_outbound": gapSocketOwner, "bad_asn_outbound": gapPartialSocketOwner,
	}
	for _, c := range entries {
		if want := required[c.Name]; c.CorrelationGap != want {
			return &gapMismatch{name: c.Name, got: c.CorrelationGap, want: want}
		}
	}
	return nil
}

type gapMismatch struct{ name, got, want string }

func (g *gapMismatch) Error() string {
	return "check " + g.name + ": gap " + g.got + ", want " + g.want
}

func TestCorrelationIndexIsImmutableAndConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !securityEventEligible("webshell") || IsDerivedCorrelationCheck("webshell") {
				t.Error("concurrent lookup disagrees")
			}
			d := DerivedCorrelationChecks()
			d[0] = "x"
		}()
	}
	wg.Wait()
	if DerivedCorrelationChecks()[0] != "coordinated_attack" {
		t.Fatal("derived list mutated through a caller-owned copy")
	}
}
