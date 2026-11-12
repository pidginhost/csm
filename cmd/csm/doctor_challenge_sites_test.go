package main

import (
	"errors"
	"strings"
	"testing"
)

func TestChallengeHTTPSSitesCheck(t *testing.T) {
	if _, ok := challengeHTTPSSitesCheck(false, false, "", nil); ok {
		t.Fatal("a stack without per-site includes got an HTTPS sites check")
	}
	check, ok := challengeHTTPSSitesCheck(true, false, "/etc/apache2/conf.d/userdata/csm-challenge.conf", nil)
	if !ok || check.Status != "warn" || !strings.Contains(check.Fix, "csm webserver-integration upgrade") {
		t.Fatalf("uncovered HTTPS sites = %+v, %v; want a warning naming the upgrade", check, ok)
	}
	check, ok = challengeHTTPSSitesCheck(true, true, "/etc/apache2/conf.d/userdata/csm-challenge.conf", nil)
	if !ok || check.Status != "ok" {
		t.Fatalf("covered HTTPS sites = %+v, %v; want ok", check, ok)
	}
	check, ok = challengeHTTPSSitesCheck(true, false, "/etc/apache2/conf.d/userdata/csm-challenge.conf", errors.New("permission denied"))
	if !ok || check.Status != "warn" {
		t.Fatalf("unreadable httpd.conf = %+v, %v; want warn", check, ok)
	}
}
