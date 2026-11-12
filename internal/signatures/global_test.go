package signatures

import "testing"

// Verdict caches key on this generation. An edit to an existing rule keeps
// the rule count and the file version, so only a per-load counter retires
// the verdicts reached under the old rules.
func TestCacheGenerationChangesOnEveryLoad(t *testing.T) {
	s := NewScanner(t.TempDir())
	before := CacheGeneration()
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	reloaded := CacheGeneration()
	if reloaded == before {
		t.Fatal("Reload kept the cache generation")
	}
	previous := SetGlobal(s)
	t.Cleanup(func() { SetGlobal(previous) })
	if CacheGeneration() == reloaded {
		t.Fatal("SetGlobal kept the cache generation")
	}
}
