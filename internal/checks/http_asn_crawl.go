// Package checks: http_asn_crawl detector — single-ASN distributed crawl of
// uncacheable URLs saturating one account's PHP pool. See
// docs/superpowers/specs/2026-06-24-http-asn-crawl-detector-design.md.
package checks

import (
	"net/url"
	"path"
	"strings"
)

// httpASNCrawlStaticExts are path extensions whose responses are cacheable
// static assets; requests for them never reach PHP, so they are not
// "expensive" for this detector.
var httpASNCrawlStaticExts = map[string]struct{}{
	"jpg": {}, "jpeg": {}, "png": {}, "gif": {}, "webp": {}, "svg": {}, "ico": {},
	"bmp": {}, "css": {}, "js": {}, "mjs": {}, "map": {}, "woff": {}, "woff2": {},
	"ttf": {}, "eot": {}, "otf": {}, "mp4": {}, "webm": {}, "ogg": {}, "mp3": {},
	"pdf": {}, "zip": {}, "gz": {}, "avif": {},
}

// httpASNCrawlExpensive reports whether a request is a dynamic, uncacheable
// hit that reaches PHP: a GET or HEAD with a query string whose path extension
// is not a static asset.
func httpASNCrawlExpensive(rec accessLogRecord) bool {
	if rec.Method != "GET" && rec.Method != "HEAD" {
		return false
	}
	q := strings.IndexByte(rec.URI, '?')
	if q < 0 || q == len(rec.URI)-1 {
		return false
	}
	p := rec.URI[:q]
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(p), "."))
	if ext == "" {
		return true
	}
	_, isStatic := httpASNCrawlStaticExts[ext]
	return !isStatic
}

// httpASNCrawlAmplifyKeys are query parameter names that signal an
// expensive layered-nav/search request; their presence raises severity.
var httpASNCrawlAmplifyKeys = map[string]struct{}{
	"orderby": {}, "add-to-cart": {}, "s": {}, "paged": {}, "product-page": {},
}

// httpASNCrawlAmplified reports whether the URI's query carries a known
// expensive layered-nav/search parameter. Key names are matched
// case-insensitively; values alone never match.
func httpASNCrawlAmplified(uri string) bool {
	q := strings.IndexByte(uri, '?')
	if q < 0 {
		return false
	}
	vals, err := url.ParseQuery(uri[q+1:])
	if err != nil {
		return false
	}
	for k := range vals {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "filter_") || strings.HasPrefix(lk, "query_type_") {
			return true
		}
		if _, ok := httpASNCrawlAmplifyKeys[lk]; ok {
			return true
		}
	}
	return false
}
