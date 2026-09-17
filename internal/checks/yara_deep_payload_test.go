package checks

import (
	"strings"
	"testing"
)

// The deep scan is the layer that finds a loader already sitting on disk. Its
// finding named the modified PHP file and nothing else, so the payload it
// pulls in -- a picture in a plugin asset directory, untouched by any
// clean-up of the PHP -- had to be found by hand.
func TestScheduledYARADetailsNameTheIncludedPayload(t *testing.T) {
	const payloadPath = "/home/site/public_html/wp-content/plugins/demo/assets/lib/images/light_square/btn.png"
	loader := []byte(`<?php if(isset($_COOKIE["sess_kx"])){$incName="` + payloadPath + `"; include($incName); exit;}`)

	got := scheduledYARADetails("backdoor_include_nonexecutable", loader)
	if !strings.Contains(got, "backdoor_include_nonexecutable") {
		t.Errorf("details lost the rule name: %q", got)
	}
	if !strings.Contains(got, payloadPath) {
		t.Errorf("details do not name the payload: %q", got)
	}
}

func TestScheduledYARADetailsStayShortWithoutAPayload(t *testing.T) {
	got := scheduledYARADetails("webshell_c99", []byte("<?php system($_GET['c']);"))
	if strings.Contains(got, "\n") {
		t.Errorf("details grew a payload line with no payload to name: %q", got)
	}
}
