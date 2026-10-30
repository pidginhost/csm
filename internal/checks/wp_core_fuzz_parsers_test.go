package checks

import "testing"

func FuzzWPCLIPHPDeprecation(f *testing.F) {
	f.Add(wpCorePHPDeprecationLogged, uint64(20))
	f.Add(wpCorePHPDeprecationDisplayed, uint64(30))
	f.Add("PHP Deprecated: synthetic diagnostic in Unknown on line 0", uint64(45))
	f.Add("", uint64(0))
	f.Fuzz(func(t *testing.T, line string, offset uint64) {
		at := int(offset % uint64(len(line)+1))
		// A claim may land inside either the message or its source location.
		// None can be made skippable by surrounding it with arbitrary output.
		for _, claim := range []string{
			"Warning: File doesn't verify against checksum: wp-includes/load.php",
			"wp-includes/load.php doesn't verify against checksum.",
			"File should not exist: wp-includes/extra.php",
			"File should exist: wp-includes/load.php",
			"File doesn't exist: wp-includes/load.php",
			"Error: unreadable directory",
			"Success: WordPress installation verifies against checksums.",
			"PHP Warning: opendir(): Permission denied",
		} {
			if wpCLIPHPDeprecation(line[:at] + claim + line[at:]) {
				t.Fatalf("deprecation filter swallowed %q", claim)
			}
		}
	})
}
