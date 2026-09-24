// Package responsereplay replays recorded finding streams through models of
// the automatic response admission path, so capacity and fairness changes
// can be measured against what hosts actually saw.
//
// Production code here imports only the standard library. The checks and
// firewall test suites import this package to run their real code beside
// the models; a CSM import here would close an import cycle through them.
//
// A replay is a hypothesis, not a record: a recording holds findings, not
// scans, queue drops, action outcomes or reviews, and every result says
// which of those it had to assume.
package responsereplay
