package platform

import (
	"path/filepath"
	"testing"
)

func FuzzAccountRootPattern(f *testing.F) {
	for _, seed := range []string{"/srv/accounts/*/public", "/srv/[", "/srv/../etc", "/*/public", "/home[2-9]/*/public_html"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, pattern string) {
		if ValidateAccountRootPattern(pattern) == nil && (!filepath.IsAbs(pattern) || filepath.Clean(pattern) != pattern) {
			t.Fatalf("accepted unconfined root %q", pattern)
		}
	})
}

func FuzzLiteSpeedServerXML(f *testing.F) {
	for _, seed := range []string{
		`<httpServerConfig><user>www-data</user><phpSuExec>1</phpSuExec></httpServerConfig>`,
		`<httpServerConfig><!-- <phpSuExec>1</phpSuExec> --><user>www-data</user></httpServerConfig>`,
		`<httpServerConfig><phpSuExec>1</phpSuExec><phpSuExec>0</phpSuExec></httpServerConfig>`,
		`<httpServerConfig><phpSuExec>1</phpSuExec>`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data string) {
		_, isolated, err := parseLiteSpeedServerXML([]byte(data))
		if err != nil || !isolated {
			return
		}
		for _, invalid := range []string{data + "garbage", "<virtualHost>" + data + "</virtualHost>", data + data} {
			if _, trusted, err := parseLiteSpeedServerXML([]byte(invalid)); err == nil || trusted {
				t.Fatal("a nested, repeated or incomplete server document proved isolation")
			}
		}
	})
}

func FuzzOpenLiteSpeedServerUser(f *testing.F) {
	for _, seed := range []string{"user site1", "user site1 # comment", "app {\nuser site1\n}", "}\nuser site1\n{"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data string) {
		user, err := openLiteSpeedServerUser("user www-data\napplication {\n" + data + "\n}\n")
		if err == nil && user != "www-data" {
			t.Fatalf("application settings replaced the server user with %q", user)
		}
	})
}

func FuzzProcNoUserspace(f *testing.F) {
	for _, seed := range []string{"worker", "x) Z", "x\n) S (y", "", ")"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		// The task name is attacker controlled, including parentheses and
		// newlines. Only fields after the final delimiter prove liveness.
		stat := "300 (" + name + ") "
		if inactive, err := procNoUserspace(stat + "S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1"); err != nil || inactive {
			t.Fatalf("live task excluded: %v, %v", inactive, err)
		}
		if inactive, err := procNoUserspace(stat + "Z 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 2 0 1"); err == nil || inactive {
			t.Fatalf("surviving thread excluded: %v, %v", inactive, err)
		}
	})
}
