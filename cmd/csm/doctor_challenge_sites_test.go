package main

import (
	"errors"
	"strings"
	"testing"
)

func TestChallengeSitesCheck(t *testing.T) {
	const path = "/etc/apache2/conf.d/userdata/csm-challenge.conf"
	const fix = "run `csm webserver-integration upgrade`"
	if _, ok := challengeSitesCheck(false, false, "", "", "", nil); ok {
		t.Fatal("a stack without per-site includes got a sites check")
	}
	check, ok := challengeSitesCheck(true, false, path, "HTTPS sites", fix, nil)
	if !ok || check.Status != "warn" || check.Fix != fix || !strings.Contains(check.Message, "HTTPS sites do not read") {
		t.Fatalf("uncovered sites = %+v, %v; want a warning with the stack's fix", check, ok)
	}
	plainFix := "add `Include /var/cache/csm/apache-challenge-site.conf` inside every <VirtualHost>, then reload Apache"
	check, ok = challengeSitesCheck(true, false, "/var/cache/csm/apache-challenge-site.conf", "Apache sites", plainFix, nil)
	if !ok || check.Fix != plainFix || !strings.Contains(check.Message, "Apache sites do not read") {
		t.Fatalf("plain Apache = %+v, %v", check, ok)
	}
	check, ok = challengeSitesCheck(true, true, path, "HTTPS sites", fix, nil)
	if !ok || check.Status != "ok" {
		t.Fatalf("covered sites = %+v, %v; want ok", check, ok)
	}
	check, ok = challengeSitesCheck(true, false, path, "HTTPS sites", fix, errors.New("permission denied"))
	if !ok || check.Status != "warn" {
		t.Fatalf("unreadable configuration = %+v, %v; want warn", check, ok)
	}
}
