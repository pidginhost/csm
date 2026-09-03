package checks

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Re-check for the web_exposed_* family.
//
// Remediating one of these findings means the file stops being downloadable --
// usually because CSM's own virtual patch denied it, sometimes because the
// operator deleted it. Neither outcome changes the finding, so without a
// verifier the family only ever accumulates: a production host carried 243 of
// them, every one already answering 403, drowning the live findings they sat
// next to.
//
// The re-check repeats the detection-time probe and clears the finding only
// when the same rule detection uses (confirmExposure) no longer calls it an
// exposure. It fails closed everywhere else, because a probe that could not be
// completed proves nothing.

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

// exposedFilePathFromDetails recovers the on-disk path from the finding details
// ("File: <path> (<n> bytes), served as ..."), for stored findings that carry
// no separate path field.
func exposedFilePathFromDetails(details string) string {
	const marker = "File: "
	i := strings.Index(details, marker)
	if i < 0 {
		return ""
	}
	rest := details[i+len(marker):]
	j := strings.Index(rest, " (")
	if j < 0 {
		return ""
	}
	path := strings.TrimSpace(rest[:j])
	if !strings.HasPrefix(path, "/") {
		return ""
	}
	return path
}

// servingIPForDomain finds the vhost row for domain and returns the address the
// probe must dial. An empty result means this host does not serve the domain.
func servingIPForDomain(domain string) string {
	content, err := osFS.ReadFile(userdataDomainsPath)
	if err != nil {
		return ""
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	for _, vh := range parseUserdataDomains(string(content)) {
		if vh.domain == domain {
			return probeHost(vh)
		}
	}
	return ""
}

// verifyExposedFile re-probes a web_exposed_* finding and resolves it when the
// file is gone or the server no longer serves it as a confirmed exposure.
func verifyExposedFile(in VerifyInput) VerifyResult {
	class, ok := exposedClassForCheck(in.Check)
	if !ok {
		return VerifyResult{Checked: false, Detail: fmt.Sprintf("unknown exposure class for '%s'", in.Check)}
	}

	// The cheapest and most certain answer: the file is no longer there.
	path := in.Path
	if path == "" {
		path = exposedFilePathFromDetails(in.Details)
	}
	if path != "" {
		if _, err := osFS.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return VerifyResult{Checked: true, Resolved: true,
					Detail: fmt.Sprintf("file no longer present: %s", path)}
			}
			return VerifyResult{Checked: false, Detail: fmt.Sprintf("cannot stat %s: %v", path, err)}
		}
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

	// Pin to this host's own serving address. Resolving the domain through
	// public DNS would ask whoever owns it now: a domain that has migrated away
	// answers from its new provider, and that answer -- 200 with the new site's
	// HTML, or a clean 404 -- says nothing about what this server exposes.
	host := servingIPForDomain(domain)
	if host == "" {
		return VerifyResult{Checked: false,
			Detail: fmt.Sprintf("%s is no longer served by this host; re-check cannot reach the original vhost", domain)}
	}

	pr := webProber.probe(context.Background(), domain, host, u.Path)
	if !pr.reachable {
		return VerifyResult{Checked: false,
			Detail: fmt.Sprintf("could not reach %s to re-check; leaving the finding open", domain)}
	}
	if pr.partial {
		return VerifyResult{Checked: false,
			Detail: "only one protocol answered; leaving the finding open until a complete probe"}
	}
	if confirmExposure(class, pr) {
		return VerifyResult{Checked: true, Resolved: false,
			Detail: fmt.Sprintf("still downloadable: HTTP %d %s", pr.status, pr.contentType)}
	}
	return VerifyResult{Checked: true, Resolved: true,
		Detail: fmt.Sprintf("no longer served as an exposure (HTTP %d %s)", pr.status, pr.contentType)}
}
