package config

import "testing"

func TestVirtualPatchMode_Normalizes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", VirtualPatchOff},
		{"off", VirtualPatchOff},
		{"nonsense", VirtualPatchOff},
		{"Manual", VirtualPatchManual},
		{" auto ", VirtualPatchAuto},
	}
	for _, tc := range cases {
		c := &Config{}
		c.AutoResponse.VirtualPatchExposedFiles = tc.in
		if got := c.VirtualPatchMode(); got != tc.want {
			t.Errorf("VirtualPatchMode(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestValidate_VirtualPatchMode(t *testing.T) {
	// Valid values (and empty) produce no error on this key.
	for _, v := range []string{"", "off", "manual", "auto", "AUTO"} {
		c := &Config{}
		c.AutoResponse.VirtualPatchExposedFiles = v
		for _, r := range Validate(c) {
			if r.Field == "auto_response.virtual_patch_exposed_files" && r.Level == "error" {
				t.Errorf("value %q wrongly rejected: %s", v, r.Message)
			}
		}
	}
	// Invalid value must produce an error on this key.
	c := &Config{}
	c.AutoResponse.VirtualPatchExposedFiles = "enforce"
	found := false
	for _, r := range Validate(c) {
		if r.Field == "auto_response.virtual_patch_exposed_files" && r.Level == "error" {
			found = true
		}
	}
	if !found {
		t.Error("invalid virtual_patch_exposed_files value should be rejected")
	}
}
