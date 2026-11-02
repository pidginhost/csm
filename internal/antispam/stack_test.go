package antispam

import "testing"

// Exim hosts keep their installed generation while the Postfix stack lands:
// a changed generation makes every cPanel host reinstall.
func TestGenerationUnchangedForExim(t *testing.T) {
	content, err := ManagedContent(defaults(false))
	if err != nil {
		t.Fatal(err)
	}
	const want = "91c71e7c6dcfcf310c50f54803562e9abffa8b8ea5fea81279db883fb5cc48eb"
	if got := Generation(content); got != want {
		t.Fatalf("Exim generation %s, want %s", got, want)
	}
}
