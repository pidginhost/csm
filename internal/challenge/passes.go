package challenge

import (
	"net/http"
	"sync"

	"github.com/pidginhost/csm/internal/metrics"
)

// How a visitor passed a challenge, the method label of
// csm_challenge_passed_total.
const (
	passMethodPoW          = "pow"
	passMethodCaptcha      = "captcha"
	passMethodVerifyCookie = "verify_cookie"
	passMethodAdminCookie  = "admin_cookie"
	passMethodCrawler      = "crawler"
)

var (
	challengePassedMetric     *metrics.CounterVec
	challengePassedMetricOnce sync.Once
)

func challengePassedCounter() *metrics.CounterVec {
	challengePassedMetricOnce.Do(func() {
		challengePassedMetric = metrics.NewCounterVec(
			"csm_challenge_passed_total",
			"Challenged addresses that passed, by method (pow, captcha, verify_cookie, admin_cookie, crawler).",
			[]string{"method"},
		)
		metrics.MustRegister("csm_challenge_passed_total", challengePassedMetric)
	})
	return challengePassedMetric
}

func observeChallengePassed(method string) {
	challengePassedCounter().With(method).Inc()
}

// PassedCount returns how many challenged addresses passed since start.
func PassedCount() int {
	c := challengePassedCounter()
	total := 0.0
	for _, m := range []string{passMethodPoW, passMethodCaptcha, passMethodVerifyCookie, passMethodAdminCookie, passMethodCrawler} {
		total += c.With(m).Value()
	}
	return int(total)
}

// bypassMethod names the shortcut that lets a pending visitor through
// without the puzzle, or "" when none applies. The order is the order the
// shortcuts are tried in.
func (s *Server) bypassMethod(r *http.Request, ip string) string {
	switch {
	case s.bypassByAdminCookie(r, ip):
		return passMethodAdminCookie
	case s.bypassByVerifiedCrawler(r.Context(), ip):
		return passMethodCrawler
	case s.bypassByVerifyCookie(r, ip):
		return passMethodVerifyCookie
	}
	return ""
}
