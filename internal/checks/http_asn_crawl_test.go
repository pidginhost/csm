package checks

import "testing"

func TestHTTPASNCrawlExpensive(t *testing.T) {
	cases := []struct {
		name string
		rec  accessLogRecord
		want bool
	}{
		{"dynamic GET with query", accessLogRecord{Method: "GET", URI: "/categorie/coliere/?filter_x=1"}, true},
		{"dynamic HEAD with query", accessLogRecord{Method: "HEAD", URI: "/shop/?orderby=price"}, true},
		{"no query string", accessLogRecord{Method: "GET", URI: "/categorie/coliere/"}, false},
		{"POST excluded", accessLogRecord{Method: "POST", URI: "/cart/?add=1"}, false},
		{"static jpg with query", accessLogRecord{Method: "GET", URI: "/img/a.jpg?v=2"}, false},
		{"static CSS uppercase ext with query", accessLogRecord{Method: "GET", URI: "/a.CSS?v=2"}, false},
		{"dot only in query, no ext", accessLogRecord{Method: "GET", URI: "/path?file=a.css"}, true},
		{"woff2 font with query", accessLogRecord{Method: "GET", URI: "/f.woff2?d=1"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := httpASNCrawlExpensive(c.rec); got != c.want {
				t.Fatalf("httpASNCrawlExpensive(%q %q)=%v want %v", c.rec.Method, c.rec.URI, got, c.want)
			}
		})
	}
}

func TestHTTPASNCrawlAmplified(t *testing.T) {
	cases := []struct {
		uri  string
		want bool
	}{
		{"/c/?filter_color=red", true},
		{"/c/?query_type_x=or", true},
		{"/shop/?orderby=price", true},
		{"/?s=ring", true},
		{"/?add-to-cart=42", true},
		{"/c/?paged=3", true},
		{"/c/?product-page=2", true},
		{"/c/?color=red", false},       // value not key
		{"/c/?ORDERBY=price", true},    // case-insensitive key
		{"/c/?x=orderby", false},       // orderby only as value
		{"/c/", false},                 // no query
		{"/c/?%zz", false},             // malformed query, no match
	}
	for _, c := range cases {
		t.Run(c.uri, func(t *testing.T) {
			if got := httpASNCrawlAmplified(c.uri); got != c.want {
				t.Fatalf("httpASNCrawlAmplified(%q)=%v want %v", c.uri, got, c.want)
			}
		})
	}
}
