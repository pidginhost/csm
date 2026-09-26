// Package crawlid is the canonical request identity shared by the
// http_pattern_crawl detector and the PHP shield crawl gate. Every rule has a
// PHP twin; testdata/vectors.json defines the shared contract.
// Case folding and ordering are byte-based ASCII only.
package crawlid

// Version is the identity contract version. Any change to a canonicalization
// rule, key encoding or binding form bumps it and the vector file together.
const Version = 1
