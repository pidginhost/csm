package checks

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// Exposure verification shares the detection-time confirmation rule and only
// clears a finding after a complete probe pinned to the current local vhost.

// exposedVerifiableChecks is the web_exposed_* family, keyed the same way the
// findings are.
var exposedVerifiableChecks = []string{
	"web_exposed_repo_metadata",
	"web_exposed_config_leak",
	"web_exposed_db_dump",
	"web_exposed_backup_archive",
	"web_exposed_source_backup",
	"web_exposed_phpinfo",
	"web_exposed_sample_sql",
}

// exposedReverifyLogicVersion is part of the daemon sweep token. Bump it when
// unattended exposure verification semantics change so existing findings are
// revisited once after upgrade.
const exposedReverifyLogicVersion = 1

// isExposedVerifiable reports whether check belongs to the web_exposed_* family,
// whose findings the automatic sweep may re-probe and dismiss.
func isExposedVerifiable(check string) bool {
	for _, c := range exposedVerifiableChecks {
		if c == check {
			return true
		}
	}
	return false
}

// exposedClassForCheck is the inverse of exposedClass.findingName. The class
// decides what counts as a confirmed exposure, so verification has to recover
// it or it would judge a phpinfo page by the raw-leak rule.
func exposedClassForCheck(check string) (exposedClass, bool) {
	for _, c := range []exposedClass{
		classRepoMetadata, classConfigLeak, classDBDump, classBackupArchive,
		classSourceBackup, classPHPInfo, classSampleSQL,
	} {
		if c.findingName() == check {
			return c, true
		}
	}
	return classNone, false
}

// exposureURLFromMessage pulls the probed URL back out of the finding message
// ("Web-exposed <label> reachable at <url>").
func exposureURLFromMessage(message string) string {
	const marker = " reachable at "
	i := strings.Index(message, marker)
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(message[i+len(marker):])
}

type exposureVhostIndex struct {
	servingIPs map[string]string
	complete   bool
}

func loadExposureVhostIndex() exposureVhostIndex {
	index := exposureVhostIndex{servingIPs: map[string]string{}}
	content, err := osFS.ReadFile(userdataDomainsPath)
	if err != nil {
		return index
	}
	vhosts, complete := parseUserdataDomainsChecked(string(content))
	index.complete = complete
	for _, vh := range vhosts {
		host := probeHost(vh)
		if previous, exists := index.servingIPs[vh.domain]; exists {
			if previous != host {
				index.complete = false
			}
			continue
		}
		index.servingIPs[vh.domain] = host
	}
	return index
}

func (index exposureVhostIndex) servingIPForDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return index.servingIPs[domain]
}

// verifyExposedFile re-probes a web_exposed_* finding and resolves it only when
// a complete pinned probe says the server no longer serves the exposure.
func verifyExposedFile(in VerifyInput) VerifyResult {
	vhosts := in.exposureVhosts
	if vhosts == nil {
		loaded := loadExposureVhostIndex()
		vhosts = &loaded
	}
	return verifyExposedFileWithVhosts(in, vhosts)
}

func verifyExposedFileWithVhosts(in VerifyInput, vhosts *exposureVhostIndex) VerifyResult {
	ctx := in.Context
	if ctx == nil {
		ctx = context.Background()
	}
	class, ok := exposedClassForCheck(in.Check)
	if !ok {
		return VerifyResult{Checked: false, Detail: fmt.Sprintf("unknown exposure class for '%s'", in.Check)}
	}

	raw := exposureURLFromMessage(in.Message)
	if raw == "" {
		return VerifyResult{Checked: false, Detail: "could not extract the exposure URL from the finding"}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Path == "" {
		return VerifyResult{Checked: false, Detail: fmt.Sprintf("unusable exposure URL %q", raw)}
	}
	domain := u.Hostname()
	if !validProbeDomain(domain) {
		return VerifyResult{Checked: false, Detail: fmt.Sprintf("unusable exposure domain %q", domain)}
	}
	if !vhosts.complete {
		return VerifyResult{Checked: false,
			Detail: "local vhost routing is incomplete; re-check cannot select a trusted serving address"}
	}

	// Pin to this host's own serving address. Resolving the domain through
	// public DNS would ask whoever owns it now: a domain that has migrated away
	// answers from its new provider, and that answer -- 200 with the new site's
	// HTML, or a clean 404 -- says nothing about what this server exposes.
	host := vhosts.servingIPForDomain(domain)
	if host == "" {
		return VerifyResult{Checked: false,
			Detail: fmt.Sprintf("%s is no longer served by this host; re-check cannot reach the original vhost", domain)}
	}

	pr := webProber.probeComplete(ctx, domain, host, u.Path)
	if !pr.reachable {
		return VerifyResult{Checked: false,
			Detail: fmt.Sprintf("could not reach %s to re-check; leaving the finding open", domain)}
	}
	if pr.partial {
		return VerifyResult{Checked: false,
			Detail: "only one protocol answered; leaving the finding open until a complete probe"}
	}
	if confirmExposure(class, pr) {
		if class == classPHPInfo {
			_, exposed, complete := confirmPHPInfoBody(ctx, pr.scheme, domain, host, u.Path)
			switch {
			case exposed:
				return VerifyResult{Checked: true, Resolved: false,
					Detail: "still downloadable: confirmed phpinfo output"}
			case !complete:
				return VerifyResult{Checked: false,
					Detail: "could not complete phpinfo body confirmation; leaving the finding open"}
			}
			return VerifyResult{Checked: true, Resolved: true,
				Detail: "no longer served as confirmed phpinfo output"}
		}
		return VerifyResult{Checked: true, Resolved: false,
			Detail: fmt.Sprintf("still downloadable: HTTP %d %s", pr.status, pr.contentType)}
	}
	return VerifyResult{Checked: true, Resolved: true,
		Detail: fmt.Sprintf("no longer served as an exposure (HTTP %d %s)", pr.status, pr.contentType)}
}
