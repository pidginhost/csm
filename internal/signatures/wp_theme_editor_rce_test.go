package signatures

import "testing"

// The rule keyed on wp_update_theme, which is not a WordPress function: it
// matched core's wp_update_themes as a substring, and its regex asked only for
// the letters "php" after it. What it claims to detect is a script pushing PHP
// into a theme file through the editor endpoint.

func TestWpThemeEditorRCE_EditorPush(t *testing.T) {
	s := loadRepoScanner(t)
	mal := []byte(`<?php
$payload = "<?php @system($_GET['c']); ?>";
$fields = http_build_query(array('action' => 'update', 'theme' => 'twentytwenty', 'file' => '404.php', 'newcontent' => $payload));
$ch = curl_init('https://victim.example.test/wp-admin/theme-editor.php');
curl_setopt($ch, CURLOPT_POSTFIELDS, $fields);
curl_exec($ch);
`)
	if !hasRule(s.ScanContent(mal, ".php"), "wp_theme_editor_rce") {
		t.Error("wp_theme_editor_rce gap: script pushing PHP through the theme editor not detected")
	}
}

func TestWpThemeEditorRCE_CoreUpdateHelper(t *testing.T) {
	s := loadRepoScanner(t)
	core := []byte(`<?php
// Core update helper: the editor link sits beside the theme update check.
function wp_update_themes($extra_stats = array()) {
    $updates = get_site_transient('update_themes');
    return $updates;
}
$actions['edit'] = '<a href="theme-editor.php?theme=' . $stylesheet . '">' . __('Edit') . '</a>';
`)
	if hasRule(s.ScanContent(core, ".php"), "wp_theme_editor_rce") {
		t.Error("wp_theme_editor_rce FP: core theme update helper beside an editor link matched")
	}
	screen := []byte(`<?php
// The editor screen itself: it names its own form field and its own endpoint.
$content = wp_unslash($_POST['newcontent']);
wp_redirect(admin_url('theme-editor.php?file=' . $file . '&updated=true'));
`)
	if hasRule(s.ScanContent(screen, ".php"), "wp_theme_editor_rce") {
		t.Error("wp_theme_editor_rce FP: the editor screen's own request handling matched")
	}
}
