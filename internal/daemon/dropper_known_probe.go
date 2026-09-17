package daemon

// dropperUploadExecutionProbes are the exact scripts Really Simple Security
// copies into the uploads directory, requests over HTTP to learn whether PHP
// runs there, and deletes again. The plugin renamed itself once, so both
// shipped versions of the comment are listed.
//
// Only exact bytes qualify. The script is code, and no parser has to judge
// it: any added statement, encoding change or trailing byte stops the match,
// and a fixed byte string cannot carry a payload an attacker chose under any
// source encoding.
var dropperUploadExecutionProbes = []string{
	"<?php\n/**\n * Test file for Really Simple SSL to check if uploads directory has code execution permissions\n *\n */\n\necho \"RSSSL CODE EXECUTION MARKER\";\n",
	"<?php\n/**\n * Test file for Really Simple Security to check if uploads directory has code execution permissions\n *\n */\n\necho \"RSSSL CODE EXECUTION MARKER\";\n",
}

// dropperCandidateIsKnownProbe reports whether the snapshot is, in full, a
// plugin's server capability test script.
func dropperCandidateIsKnownProbe(c dropperCandidate) bool {
	if c.Mode&0o111 != 0 || c.Size != int64(len(c.Head)) {
		return false
	}
	for _, probe := range dropperUploadExecutionProbes {
		if string(c.Head) == probe {
			return true
		}
	}
	return false
}

// dropperCandidateIsHarmless reports whether the snapshot cannot be a dropper
// payload: it has no executable statement, or it is a known test script.
func dropperCandidateIsHarmless(c dropperCandidate) bool {
	return dropperCandidateIsInert(c) || dropperCandidateIsKnownProbe(c)
}
