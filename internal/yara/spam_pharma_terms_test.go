//go:build yara

package yara

import "testing"

// The pharma doorway rule proves its three signals sit together but reads a
// drug list that omits the words the doorways actually use.

func TestSpamPharma_DrugListGaps(t *testing.T) {
	s := loadRepoYaraScanner(t)
	for _, mal := range [][]byte{
		[]byte(`<div style="display:none">Order now from our online pharmacy, no prescription needed.</div>`),
		[]byte(`<div style="visibility:hidden">Buy online ambien and sleep aids shipped worldwide.</div>`),
		[]byte(`<div style="display:none">Achetez en ligne: pharmacie en ligne, cheap online delivery.</div>`),
	} {
		if !hasYaraRule(s.ScanBytes(mal), "spam_pharma") {
			t.Errorf("spam_pharma gap: hidden pharma doorway not detected: %s", mal)
		}
	}
	legit := []byte(`<div style="display:none">Buy now and save on every order.</div><p>Shop our winter sale.</p>`)
	if hasYaraRule(s.ScanBytes(legit), "spam_pharma") {
		t.Error("spam_pharma FP: hidden promotional markup without a drug name matched")
	}
}
