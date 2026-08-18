package phptaint

import "bytes"

// sinkKeywords and sourceKeywords drive admission only. They are language
// constructs and library function names, never variable or file names.
var (
	sinkKeywords = [][]byte{
		[]byte("eval"), []byte("include"), []byte("require"),
		[]byte("assert"), []byte("create_function"),
	}
	sourceKeywords = [][]byte{
		[]byte("curl_exec"), []byte("curl_multi_getcontent"),
		[]byte("file_get_contents"), []byte("fopen"), []byte("fread"),
		[]byte("fgets"), []byte("stream_get_contents"), []byte("readfile"),
		[]byte("wp_remote_retrieve_body"), []byte("wp_remote_get"),
		[]byte("fsockopen"),
	}
	phpOpenTags = [][]byte{[]byte("<?php"), []byte("<?="), []byte("<?")}
)

// isCandidate is a cheap byte scan run before parsing. It is intentionally
// over-inclusive; the AST pass decides whether a real flow exists.
func isCandidate(src []byte) bool {
	lower := bytes.ToLower(src)
	if !containsAny(lower, phpOpenTags) {
		return false
	}
	return containsAny(lower, sinkKeywords) && containsAny(lower, sourceKeywords)
}

func containsAny(hay []byte, needles [][]byte) bool {
	for _, n := range needles {
		if bytes.Contains(hay, n) {
			return true
		}
	}
	return false
}
