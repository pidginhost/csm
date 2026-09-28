// Package crawlreplay replays anonymized domlog record streams through exact
// models of the http_pattern_crawl detector, so window, baseline, residual
// and sketch settings can be chosen from traffic hosts actually served.
//
// Production code here imports only the standard library. A replay is a
// hypothesis about the detector, not a record of what a host did: a stream
// holds completed requests with their logged times, not offered load, harm,
// queueing or gate outcomes, and only minutes a coverage proof certifies,
// less those with unknown loss, count as observed.
//
// Bundle validation reconciles observed site and input extents with records
// and requires every counted line to have source bytes. Decoded manifests
// and proofs retain their digest bindings: edits require re-encoding and
// decoding, and a changed manifest requires a newly bound proof. Validation
// snapshots this metadata before invoking visitors. Coverage comes only
// from certified spans after removing every possible unknown-loss minute.
//
// A ReplaySession carries detector state across chronological segments, so
// held-out minutes are judged against history learned only from earlier
// ones. It learns a minute only when the segment declares it normal, no
// finding is active and a complete window judged its traffic; gaps restart
// windows without learning zeros, and a finding stays active, pinned to the
// profile it began with, until a complete window clears it. A Scorer credits
// an episode only with a High transition at a key its private truth table
// names, whose window holds the episode's requests; a window's majority
// label is a suggestion for review. Onset is the episode's first request the
// detector counts (not infrastructure or static). An undetected episode that
// began outside the scoring spans, or none of whose counted requests was
// replayed in a scored minute, is not_scored; otherwise it is missed.
// Relevant anomalous windows retain their margins even when an already
// active finding prevents a new detection.
package crawlreplay
