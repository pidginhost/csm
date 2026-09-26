package crawlid

// StaticExtensions are path extensions served as static assets. Requests for
// them are neither dynamic nor expensive. http_asn_crawl uses this same list.
var StaticExtensions = map[string]struct{}{
	"jpg": {}, "jpeg": {}, "png": {}, "gif": {}, "webp": {}, "svg": {}, "ico": {},
	"bmp": {}, "css": {}, "js": {}, "mjs": {}, "map": {}, "woff": {}, "woff2": {},
	"ttf": {}, "eot": {}, "otf": {}, "mp4": {}, "webm": {}, "ogg": {}, "mp3": {},
	"pdf": {}, "zip": {}, "gz": {}, "avif": {},
}

// Class is the cost heuristic for one request. Dynamic means a GET or HEAD
// for a non-static extension; Expensive additionally needs a non-empty query.
// It is a heuristic, not proof of a cache miss or of PHP execution.
type Class struct {
	Dynamic   bool
	Expensive bool
}

// Classify applies the heuristic. Methods are case-sensitive, as in HTTP.
func Classify(method string, t Target) Class {
	if method != "GET" && method != "HEAD" {
		return Class{}
	}
	if _, static := StaticExtensions[t.Ext]; static {
		return Class{}
	}
	return Class{Dynamic: true, Expensive: t.HasQuery}
}
