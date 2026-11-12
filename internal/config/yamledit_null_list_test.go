package config

import (
	"reflect"
	"testing"
)

func TestYAMLEditClearsNullLists(t *testing.T) {
	for _, suffix := range []string{"", " ", " # defaults", " null", " ~"} {
		t.Run(suffix, func(t *testing.T) {
			in := []byte("backdoor_ports:" + suffix + "\nfirewall:\n  smtp_allow_users:" + suffix + "\n")
			out, err := YAMLEdit(in, []YAMLChange{
				{Path: []string{"backdoor_ports"}, Value: []int{}},
				{Path: []string{"firewall", "smtp_allow_users"}, Value: []string{}},
			})
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadBytes(out)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cfg.BackdoorPorts, []int{}) || !reflect.DeepEqual(cfg.Firewall.SMTPAllowUsers, []string{}) {
				t.Fatal("cleared lists did not remain explicitly empty")
			}
		})
	}
}
