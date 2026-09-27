// Package crawlreplay replays anonymized domlog record streams through exact
// models of the http_pattern_crawl detector, so window, baseline, residual
// and sketch settings can be chosen from traffic hosts actually served.
//
// Production code here imports only the standard library. A replay is a
// hypothesis about the detector, not a record of what a host did: a stream
// holds completed requests with their logged times, not offered load, harm,
// queueing or gate outcomes, and every report says which it assumed.
package crawlreplay
