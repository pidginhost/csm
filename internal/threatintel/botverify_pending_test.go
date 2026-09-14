package threatintel

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

func TestBotVerificationFailureCannotRenewPending(t *testing.T) {
	for _, kind := range []string{"DNS failure", "no PTR", "cache failure"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ip := net.ParseIP("192.0.2.10")
				res := &mockResolver{err: errors.New("resolver unavailable")}
				if kind == "no PTR" {
					res.err = &net.DNSError{IsNotFound: true}
				}
				if kind == "cache failure" {
					res = &mockResolver{ptr: map[string][]string{ip.String(): {"crawler.example"}}}
				}
				writes := 0
				a := NewAsyncBotVerifier(func(net.IP, string, bool, time.Time) error { writes++; return errors.New("cache unavailable") }, nil)
				a.v["googlebot"] = newVerifier(res, []string{"googlebot.com"})
				if !a.Enqueue(ip, "googlebot") || !a.Pending(ip, "googlebot") {
					t.Fatal("first job was not admitted as pending")
				}
				a.process(<-a.ch)
				if a.Pending(ip, "googlebot") {
					t.Fatal("failed verification remained pending")
				}
				if a.Enqueue(ip, "googlebot") {
					t.Error("failed lookup retried immediately")
					a.process(<-a.ch)
				}
				// A later scan may retry DNS, but must not give the same unresolved
				// source a fresh pending exemption on every scan cycle.
				time.Sleep(10 * time.Minute)
				if !a.Enqueue(ip, "googlebot") {
					t.Fatal("later retry was blocked")
				}
				if a.Pending(ip, "googlebot") {
					t.Error("unresolved retry renewed pending treatment")
				}
				a.process(<-a.ch)
				if kind != "cache failure" && writes != 0 {
					t.Fatal("resolver failure wrote a spoof verdict")
				}
			})
		})
	}
}

func TestBotPendingHistoryIsBoundedWithoutRenewalOnChurn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := NewAsyncBotVerifier(nil, nil)
		a.v["googlebot"] = newVerifier(&mockResolver{err: &net.DNSError{IsNotFound: true}}, []string{"googlebot.com"})
		for i := range 2 * cap(a.ch) {
			ip := net.ParseIP(fmt.Sprintf("2001:db8::%x", i+1))
			if i >= cap(a.ch) {
				// Every admitted job needs retained cooldown state. Otherwise
				// overflow sources can retry failed DNS on every request.
				if a.Enqueue(ip, "googlebot") || a.Pending(ip, "googlebot") {
					t.Fatal("full cooling history admitted an untracked job")
				}
				continue
			}
			if !a.Enqueue(ip, "googlebot") {
				t.Fatal("available history capacity stopped DNS work")
			}
			a.process(<-a.ch)
			if len(a.attempts) > cap(a.ch) {
				t.Fatal("attempt history exceeded queue capacity")
			}
		}
		time.Sleep(10 * time.Minute)
		ip := net.ParseIP("2001:db8::1")
		if !a.Enqueue(ip, "googlebot") || a.Pending(ip, "googlebot") {
			t.Fatal("churn evicted a retained attempt and renewed its grace")
		}
		a.process(<-a.ch)
		time.Sleep(botVerifyCacheTTL + time.Second)
		if !a.Enqueue(ip, "googlebot") || !a.Pending(ip, "googlebot") {
			t.Fatal("expired history did not release capacity")
		}
		if len(a.attempts) != 1 {
			t.Fatalf("expired attempts retained: %d", len(a.attempts))
		}
	})
}

func TestBotPendingEndsAfterStoredVerdict(t *testing.T) {
	for _, verified := range []bool{false, true} {
		t.Run(fmt.Sprint(verified), func(t *testing.T) {
			ip := net.ParseIP("192.0.2.10")
			res := &mockResolver{ptr: map[string][]string{ip.String(): {"crawler.example"}}}
			if verified {
				res = &mockResolver{ptr: map[string][]string{ip.String(): {"crawler.googlebot.com"}}, a: map[string][]net.IP{"crawler.googlebot.com": {ip}}}
			}
			stored := false
			a := NewAsyncBotVerifier(func(_ net.IP, _ string, got bool, _ time.Time) error {
				if got != verified {
					t.Errorf("stored verdict=%t, want %t", got, verified)
				}
				stored = true
				return nil
			}, nil)
			a.v["googlebot"] = newVerifier(res, []string{"googlebot.com"})
			if !a.Enqueue(ip, "googlebot") || !a.Pending(ip, "googlebot") {
				t.Fatal("job not pending after admission")
			}
			a.process(<-a.ch)
			if !stored || a.Pending(ip, "googlebot") || len(a.attempts) != 0 {
				t.Fatal("cached verdict retained unresolved verification state")
			}
		})
	}
}

func TestBotFailedRetriesCannotPinGraceCapacity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := NewAsyncBotVerifier(nil, nil)
		a.v["googlebot"] = newVerifier(&mockResolver{err: &net.DNSError{IsNotFound: true}}, []string{"googlebot.com"})
		for i := range cap(a.ch) {
			ip := net.ParseIP(fmt.Sprintf("2001:db8::%x", i+1))
			a.Enqueue(ip, "googlebot")
			a.process(<-a.ch)
		}
		// Active failures used to slide every occupied slot's expiry forever.
		for range 23 {
			time.Sleep(time.Hour)
			for i := range cap(a.ch) {
				ip := net.ParseIP(fmt.Sprintf("2001:db8::%x", i+1))
				if !a.Enqueue(ip, "googlebot") {
					t.Fatal("retry was not admitted")
				}
				a.process(<-a.ch)
			}
		}
		time.Sleep(time.Hour + time.Second)
		ip := net.ParseIP("192.0.2.10")
		if !a.Enqueue(ip, "googlebot") || !a.Pending(ip, "googlebot") {
			t.Fatal("failed retry traffic permanently denied a new crawler pending grace")
		}
	})
}

func TestBotPendingHistoryMakesRoomAfterCooldown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := NewAsyncBotVerifier(nil, nil)
		a.v["googlebot"] = newVerifier(&mockResolver{err: &net.DNSError{IsNotFound: true}}, []string{"googlebot.com"})
		for i := range cap(a.ch) {
			ip := net.ParseIP(fmt.Sprintf("2001:db8::%x", i+1))
			if !a.Enqueue(ip, "googlebot") {
				t.Fatal("initial lookup was not admitted")
			}
			a.process(<-a.ch)
		}
		time.Sleep(botVerifyRetryDelay)
		// Repeated failures must not renew every slot's protection just before
		// an unfamiliar crawler arrives, indefinitely reserving all history.
		for i := range cap(a.ch) {
			ip := net.ParseIP(fmt.Sprintf("2001:db8::%x", i+1))
			if !a.Enqueue(ip, "googlebot") || a.Pending(ip, "googlebot") {
				t.Fatal("failed retry changed the initial pending treatment")
			}
			a.process(<-a.ch)
		}
		ip := net.ParseIP("192.0.2.10")
		if !a.Enqueue(ip, "googlebot") || !a.Pending(ip, "googlebot") {
			t.Fatal("completed failures denied a new crawler pending grace after cooldown")
		}
		if len(a.attempts) > cap(a.ch) {
			t.Fatal("making room grew attempt history beyond its bound")
		}
	})
}

func TestBotOverflowCannotBypassRetryCooldown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := NewAsyncBotVerifier(nil, nil)
		a.v["googlebot"] = newVerifier(&mockResolver{err: &net.DNSError{IsNotFound: true}}, []string{"googlebot.com"})
		for i := range cap(a.ch) {
			ip := net.ParseIP(fmt.Sprintf("2001:db8::%x", i+1))
			a.Enqueue(ip, "googlebot")
			a.process(<-a.ch)
		}
		ip := net.ParseIP("192.0.2.10")
		if a.Enqueue(ip, "googlebot") {
			a.process(<-a.ch)
		}
		if a.Enqueue(ip, "googlebot") {
			t.Fatal("full attempt history allowed an immediate failed DNS retry")
		}
	})
}

func TestBotHistoryExpiryPreservesLiveAndCoolingAttempts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := NewAsyncBotVerifier(nil, nil)
		a.v["googlebot"] = newVerifier(&mockResolver{err: &net.DNSError{IsNotFound: true}}, []string{"googlebot.com"})
		ip := net.ParseIP("192.0.2.10")
		a.Enqueue(ip, "googlebot")
		job := <-a.ch
		// A blocked worker can outlive the history TTL. Admission of other
		// traffic must not remove the live job's retry protection.
		time.Sleep(botVerifyCacheTTL + time.Second)
		a.Enqueue(net.ParseIP("192.0.2.11"), "googlebot")
		a.process(job)
		if a.Enqueue(ip, "googlebot") {
			t.Fatal("history expiry bypassed the completed job's retry cooldown")
		}
	})
}
