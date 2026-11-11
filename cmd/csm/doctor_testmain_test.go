package main

import (
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// The production readers, kept for the test that exercises them.
var productionDoctorHTTPRewrite, productionDoctorPlatformOverrides = doctorHTTPRewrite, doctorPlatformOverrides

// TestMain pins host reads a doctor test must not depend on: the test
// host's web server is not the one a test describes, and installing its
// platform overrides would change other tests' detection.
func TestMain(m *testing.M) {
	doctorPlatformOverrides = func(*config.Config) bool { return true }
	doctorHTTPRewrite = func(bool) checks.HTTPRewrite { return checks.HTTPRewrite{State: checks.RewriteNone} }
	os.Exit(m.Run())
}
