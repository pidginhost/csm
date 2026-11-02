package antispam

import "testing"

// Exim hosts keep their installed generation while the Postfix stack lands:
// a changed generation makes every cPanel host reinstall.
func TestGenerationUnchangedForExim(t *testing.T) {
	content, err := ManagedContent(defaults(false))
	if err != nil {
		t.Fatal(err)
	}
	const want = "2f42a8a781c7a5db1b8611b04d2458aabc5dd032da8aeb6c79e3a02b8162ab84"
	if got := Generation(content); got != want {
		t.Fatalf("Exim generation %s, want %s", got, want)
	}
}
