package daemon

import (
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	formTestWindow = 24 * time.Hour
	formTestLimit  = 5
	formTestIP     = "203.0.113.9"
	formTestA      = scriptKey("site-a.example:/contact.php")
	formTestB      = scriptKey("site-b.example:/index.php")
)

var formTestT0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func formRecord(w *formRelayWindow, ip string, k scriptKey, cpuser, msgID string, at time.Time, unparsed bool, outside ...string) int {
	return w.record(formRelayKey(ip), ip, cpuser, k, msgID, at, outside, unparsed, formTestWindow, formTestLimit)
}

func TestFormRelayWindow_CountsDistinctOutsideRecipients(t *testing.T) {
	w := newFormRelayWindow(100)
	formRecord(w, formTestIP, formTestA, "usera", "m1", formTestT0, false, "v1@victim.example")
	formRecord(w, formTestIP, formTestB, "userb", "m2", formTestT0.Add(time.Hour), false, "v2@victim.example")
	if got := formRecord(w, formTestIP, formTestA, "usera", "m3", formTestT0.Add(2*time.Hour), false, "v3@victim.example"); got != 3 {
		t.Fatalf("count = %d, want 3", got)
	}
	if got := w.exactIP(formRelayKey(formTestIP)); got != formTestIP {
		t.Fatalf("exactIP = %q, want %q", got, formTestIP)
	}
}

func TestFormRelayWindow_SameRecipientCountsOnce(t *testing.T) {
	w := newFormRelayWindow(100)
	formRecord(w, formTestIP, formTestA, "usera", "m1", formTestT0, false, "v1@victim.example")
	if got := formRecord(w, formTestIP, formTestB, "userb", "m2", formTestT0.Add(time.Minute), false, "v1@victim.example"); got != 1 {
		t.Fatalf("count = %d, want 1", got)
	}
}

func TestFormRelayWindow_UnparsedCountsAsNew(t *testing.T) {
	w := newFormRelayWindow(100)
	formRecord(w, formTestIP, formTestA, "usera", "m1", formTestT0, true)
	if got := formRecord(w, formTestIP, formTestA, "usera", "m2", formTestT0.Add(time.Minute), true); got != 2 {
		t.Fatalf("count = %d, want 2", got)
	}
	if got := w.recipientDomains(formRelayKey(formTestIP), formTestT0); len(got) != 0 {
		t.Fatalf("unparsed entries leaked into domains: %v", got)
	}
}

func TestFormRelayWindow_WindowExpires(t *testing.T) {
	w := newFormRelayWindow(100)
	formRecord(w, formTestIP, formTestA, "usera", "m1", formTestT0, false, "v1@victim.example")
	if got := formRecord(w, formTestIP, formTestA, "usera", "m2", formTestT0.Add(25*time.Hour), false, "v2@victim.example"); got != 1 {
		t.Fatalf("count = %d, want 1 (t0 recipient expired)", got)
	}
}

func TestFormRelayWindow_StopsGrowingAtLimit(t *testing.T) {
	w := newFormRelayWindow(100)
	got := 0
	for i := 0; i < 50; i++ {
		got = formRecord(w, formTestIP, formTestA, "usera", fmt.Sprintf("m%d", i), formTestT0.Add(time.Duration(i)*time.Minute), false, fmt.Sprintf("v%d@d%d.example", i, i))
	}
	if got != formTestLimit {
		t.Fatalf("count = %d, want %d", got, formTestLimit)
	}
	if stored := w.recipientDomains(formRelayKey(formTestIP), formTestT0); len(stored) != formTestLimit {
		t.Fatalf("stored %d recipients, want %d: %v", len(stored), formTestLimit, stored)
	}
	if got := w.exactIP(formRelayKey(formTestIP)); got != formTestIP {
		t.Fatalf("last-seen not updated past the limit: exactIP = %q", got)
	}
}

func TestFormRelayWindow_RetainsRecentRecipientsAtLimit(t *testing.T) {
	for _, unparsed := range []bool{false, true} {
		t.Run(fmt.Sprintf("unparsed=%t", unparsed), func(t *testing.T) {
			w := newFormRelayWindow(100)
			key := formRelayKey(formTestIP)
			for i := 0; i < 2*formTestLimit; i++ {
				at := formTestT0
				k, user := formTestA, "usera"
				if i >= formTestLimit {
					at = at.Add(23 * time.Hour)
					k, user = formTestB, "userb"
				}
				var outside []string
				if !unparsed {
					outside = []string{fmt.Sprintf("v%d@victim.example", i)}
				}
				formRecord(w, formTestIP, k, user, fmt.Sprintf("m%d", i), at, unparsed, outside...)
			}
			now := formTestT0.Add(25 * time.Hour)
			w.sweep(now, formTestWindow)
			if got := formRecord(w, formTestIP, formTestB, "userb", "own-domain", now, false); got != formTestLimit {
				t.Fatalf("count after expiry = %d, want %d recent recipients", got, formTestLimit)
			}
			want := map[scriptKey]formRelayShare{formTestB: {Count: formTestLimit, CPUser: "userb"}}
			if got := w.scriptShares(key, now.Add(-formTestWindow)); !reflect.DeepEqual(got, want) {
				t.Fatalf("recent script shares = %v, want %v", got, want)
			}
		})
	}
}

func TestFormRelayWindow_LateRecipientsDoNotReplaceNewer(t *testing.T) {
	w := newFormRelayWindow(100)
	for i := 0; i < formTestLimit; i++ {
		formRecord(w, formTestIP, formTestB, "userb", fmt.Sprintf("m%d", i), formTestT0.Add(time.Hour), false, fmt.Sprintf("v%d@recent.example", i))
	}
	formRecord(w, formTestIP, formTestA, "usera", "late", formTestT0, false, "late@old.example")
	want := map[scriptKey]formRelayShare{formTestB: {Count: formTestLimit, CPUser: "userb"}}
	if got := w.scriptShares(formRelayKey(formTestIP), formTestT0); !reflect.DeepEqual(got, want) {
		t.Fatalf("late recipient displaced newer evidence: %v", got)
	}
}

func TestFormRelayWindow_RejectsExpiredReplay(t *testing.T) {
	for _, sweep := range []bool{false, true} {
		t.Run(fmt.Sprintf("sweep=%t", sweep), func(t *testing.T) {
			w := newFormRelayWindow(100)
			formRecord(w, formTestIP, formTestA, "usera", "old", formTestT0, false, "old@victim.example")
			now := formTestT0.Add(25 * time.Hour)
			want := 1
			if sweep {
				w.sweep(now, formTestWindow)
				want = 0
			} else {
				formRecord(w, formTestIP, formTestB, "userb", "current", now, false, "current@victim.example")
			}
			if got := formRecord(w, formTestIP, formTestA, "usera", "old", formTestT0, false, "old@victim.example"); got != want {
				t.Fatalf("expired replay changed current count: got %d, want %d", got, want)
			}
			if w.markFired(formRelayKey(formTestIP), formTestT0, formTestWindow) {
				t.Fatal("expired replay started a new cooldown")
			}
		})
	}
}

func TestFormRelayWindow_LowerLimitKeepsNewestRecipients(t *testing.T) {
	w := newFormRelayWindow(100)
	for i := 0; i < formTestLimit; i++ {
		formRecord(w, formTestIP, formTestA, "usera", fmt.Sprintf("m%d", i), formTestT0.Add(time.Duration(i)*time.Minute), false, fmt.Sprintf("v@d%d.example", i))
	}
	key := formRelayKey(formTestIP)
	if got := w.record(key, formTestIP, "usera", formTestA, "own-domain", formTestT0.Add(time.Hour), nil, false, formTestWindow, 2); got != 2 {
		t.Fatalf("count after lowering limit = %d, want 2", got)
	}
	if got := w.recipientDomains(key, formTestT0); !reflect.DeepEqual(got, []string{"d3.example", "d4.example"}) {
		t.Fatalf("retained domains = %v, want newest domains", got)
	}
}

func TestFormRelayWindow_ExpiresBeforeCapacityEviction(t *testing.T) {
	for _, fired := range []bool{false, true} {
		t.Run(fmt.Sprintf("fired=%t", fired), func(t *testing.T) {
			w := newFormRelayWindow(2)
			for i := 0; i < formTestLimit; i++ {
				formRecord(w, "192.0.2.1", formTestA, "usera", fmt.Sprintf("m%d", i), formTestT0, false, fmt.Sprintf("v%d@victim.example", i))
			}
			if fired && !w.markFired(formRelayKey("192.0.2.1"), formTestT0, formTestWindow) {
				t.Fatal("initial crossing did not fire")
			}
			formRecord(w, "192.0.2.2", formTestB, "userb", "recent", formTestT0.Add(23*time.Hour), false, "v@victim.example")
			formRecord(w, "192.0.2.3", formTestB, "userb", "new", formTestT0.Add(25*time.Hour), false, "v@victim.example")
			if got := w.exactIP(formRelayKey("192.0.2.1")); got != "" {
				t.Fatalf("expired client retained: %q", got)
			}
			for _, ip := range []string{"192.0.2.2", "192.0.2.3"} {
				if got := w.exactIP(formRelayKey(ip)); got != ip {
					t.Fatalf("active client %s lost: %q", ip, got)
				}
			}
			if w.full() {
				t.Fatal("expiry reported as capacity loss")
			}
		})
	}
}

func TestFormRelayWindow_EvictsLowCountsFirst(t *testing.T) {
	w := newFormRelayWindow(100)
	// The near-crossing client is the oldest key, so age alone would evict it.
	hot := "192.0.2.200"
	for i := 0; i < formTestLimit-1; i++ {
		formRecord(w, hot, formTestA, "usera", fmt.Sprintf("h%d", i), formTestT0, false, fmt.Sprintf("h%d@victim.example", i))
	}
	for i := 1; i <= 99; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i)
		formRecord(w, ip, formTestA, "usera", "m"+ip, formTestT0.Add(time.Duration(i)*time.Minute), false, "v@victim.example")
	}
	formRecord(w, "192.0.2.1", formTestA, "usera", "new", formTestT0.Add(200*time.Minute), false, "v@victim.example")

	if got := w.exactIP(formRelayKey(hot)); got != hot {
		t.Fatal("near-crossing key was evicted")
	}
	if got := w.exactIP(formRelayKey("198.51.100.1")); got != "" {
		t.Fatal("oldest single-recipient key survived")
	}
	for i := 2; i <= 99; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i)
		if w.exactIP(formRelayKey(ip)) != ip {
			t.Fatalf("%s evicted, only one key should go", ip)
		}
	}
	if w.exactIP(formRelayKey("192.0.2.1")) != "192.0.2.1" {
		t.Fatal("new key not stored")
	}
}

func TestFormRelayWindow_FullFlagAndSweep(t *testing.T) {
	w := newFormRelayWindow(2)
	formRecord(w, "192.0.2.1", formTestA, "usera", "m1", formTestT0, false, "v@victim.example")
	formRecord(w, "192.0.2.2", formTestA, "usera", "m2", formTestT0, false, "v@victim.example")
	if w.full() {
		t.Fatal("full before the cap was passed")
	}
	formRecord(w, "192.0.2.3", formTestA, "usera", "m3", formTestT0, false, "v@victim.example")
	if !w.full() {
		t.Fatal("full() false after inserting past the cap")
	}
	if !w.sweep(formTestT0, formTestWindow) {
		t.Fatal("first sweep did not report the cap")
	}
	if w.full() || w.sweep(formTestT0, formTestWindow) {
		t.Fatal("cap reported again without a new eviction")
	}
	w.sweep(formTestT0.Add(25*time.Hour), formTestWindow)
	if w.exactIP(formRelayKey("192.0.2.3")) != "" {
		t.Fatal("sweep kept a key whose recipients all expired")
	}
}

func TestFormRelayWindow_StaffExpiresAfterSevenDays(t *testing.T) {
	w := newFormRelayWindow(100)
	key := formRelayKey(formTestIP)
	w.markStaff("usera", key, formTestT0)
	if !w.isStaff("usera", key, formTestT0.Add(formRelayStaffTTL-time.Hour)) {
		t.Fatal("staff forgotten before seven days")
	}
	if w.isStaff("usera", key, formTestT0.Add(formRelayStaffTTL+time.Hour)) {
		t.Fatal("staff kept past seven days")
	}
	w.sweep(formTestT0.Add(formRelayStaffTTL+time.Hour), formTestWindow)
	if len(w.staff) != 0 {
		t.Fatalf("sweep kept expired staff: %v", w.staff)
	}
}

func TestFormRelayWindow_StaffIsPerAccount(t *testing.T) {
	w := newFormRelayWindow(100)
	key := formRelayKey(formTestIP)
	w.markStaff("usera", key, formTestT0)
	if w.isStaff("userb", key, formTestT0) {
		t.Fatal("staff on usera exempted the IP on userb")
	}
	if !w.isStaff("usera", key, formTestT0) {
		t.Fatal("staff not recognised on its own account")
	}
}

func TestFormRelayWindow_StaffCapPerAccount(t *testing.T) {
	w := newFormRelayWindow(100)
	for i := 1; i <= formRelayStaffPerAccount+1; i++ {
		w.markStaff("usera", formRelayKey(fmt.Sprintf("198.51.100.%d", i)), formTestT0.Add(time.Duration(i)*time.Minute))
	}
	now := formTestT0.Add(2 * time.Hour)
	if w.isStaff("usera", formRelayKey("198.51.100.1"), now) {
		t.Fatal("oldest staff IP kept past the cap")
	}
	for i := 2; i <= formRelayStaffPerAccount+1; i++ {
		if !w.isStaff("usera", formRelayKey(fmt.Sprintf("198.51.100.%d", i)), now) {
			t.Fatalf("staff IP %d evicted, only the oldest should go", i)
		}
	}
}

func TestFormRelayWindow_LateStaffDoesNotEvictNewer(t *testing.T) {
	w := newFormRelayWindow(100)
	for i := 1; i <= formRelayStaffPerAccount; i++ {
		w.markStaff("usera", formRelayKey(fmt.Sprintf("198.51.100.%d", i)), formTestT0.Add(time.Duration(i)*time.Minute))
	}
	lateKey := formRelayKey("192.0.2.1")
	w.markStaff("usera", lateKey, formTestT0)
	now := formTestT0.Add(2 * time.Hour)
	if w.isStaff("usera", lateKey, now) {
		t.Fatal("late staff record retained over newer records")
	}
	for i := 1; i <= formRelayStaffPerAccount; i++ {
		if !w.isStaff("usera", formRelayKey(fmt.Sprintf("198.51.100.%d", i)), now) {
			t.Fatalf("newer staff IP %d evicted by late record", i)
		}
	}
}

func TestFormRelayWindow_FiresOncePerWindow(t *testing.T) {
	w := newFormRelayWindow(100)
	key := formRelayKey(formTestIP)
	if !w.markFired(key, formTestT0, formTestWindow) {
		t.Fatal("first crossing did not fire")
	}
	if w.markFired(key, formTestT0.Add(time.Hour), formTestWindow) {
		t.Fatal("fired twice in one window")
	}
	w.sweep(formTestT0.Add(2*time.Hour), formTestWindow)
	if w.markFired(key, formTestT0.Add(3*time.Hour), formTestWindow) {
		t.Fatal("sweep forgot a fired key inside its window")
	}
	if !w.markFired(key, formTestT0.Add(25*time.Hour), formTestWindow) {
		t.Fatal("did not fire again in the next window")
	}
}

func TestFormRelayWindow_ScriptShares(t *testing.T) {
	w := newFormRelayWindow(100)
	formRecord(w, formTestIP, formTestA, "usera", "m1", formTestT0, false, "v1@victim.example", "v2@victim.example")
	formRecord(w, formTestIP, formTestA, "usera", "m2", formTestT0, false, "v3@victim.example")
	formRecord(w, formTestIP, formTestB, "userb", "m3", formTestT0, false, "v4@other.example")
	got := w.scriptShares(formRelayKey(formTestIP), formTestT0)
	want := map[scriptKey]formRelayShare{
		formTestA: {Count: 3, CPUser: "usera"},
		formTestB: {Count: 1, CPUser: "userb"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scriptShares = %v, want %v", got, want)
	}
	if got := w.recipientDomains(formRelayKey(formTestIP), formTestT0); !reflect.DeepEqual(got, []string{"other.example", "victim.example"}) {
		t.Fatalf("recipientDomains = %v", got)
	}
}

func TestFormRelayWindow_ConcurrentUpdatesAndSweep(t *testing.T) {
	w := newFormRelayWindow(100)
	key := formRelayKey(formTestIP)
	var fired atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			formRecord(w, formTestIP, formTestA, "usera", fmt.Sprintf("m%d", i), formTestT0, false, fmt.Sprintf("v%d@victim.example", i%formTestLimit))
			if w.markFired(key, formTestT0, formTestWindow) {
				fired.Add(1)
			}
			w.markStaff("usera", key, formTestT0)
			if !w.isStaff("usera", key, formTestT0) {
				t.Error("concurrent sweep lost staff")
			}
			if w.sweep(formTestT0, formTestWindow) || w.full() {
				t.Error("one client exceeded capacity")
			}
			if got := w.exactIP(key); got != formTestIP {
				t.Errorf("concurrent sweep lost source address: %q", got)
			}
			wantDomains := []string{"victim.example"}
			if got := w.recipientDomains(key, formTestT0); !reflect.DeepEqual(got, wantDomains) {
				t.Errorf("concurrent sweep lost recipient domains: %v", got)
			}
			shares := w.scriptShares(key, formTestT0)
			if len(shares) != 1 || shares[formTestA].Count < 1 || shares[formTestA].Count > formTestLimit || shares[formTestA].CPUser != "usera" {
				t.Errorf("invalid concurrent script shares: %v", shares)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := fired.Load(); got != 1 {
		t.Fatalf("concurrent crossings fired %d times, want 1", got)
	}
	want := map[scriptKey]formRelayShare{formTestA: {Count: formTestLimit, CPUser: "usera"}}
	if got := w.scriptShares(key, formTestT0); !reflect.DeepEqual(got, want) {
		t.Fatalf("final script shares = %v, want %v", got, want)
	}
}

func TestFormRelayKey_IPv6Slash64(t *testing.T) {
	a, b, c := formRelayKey("2001:db8::1"), formRelayKey("2001:db8::2"), formRelayKey("2001:db8:0:1::1")
	if a != b {
		t.Fatalf("same /64, different keys: %q %q", a, b)
	}
	if a == c {
		t.Fatalf("different /64, same key: %q", a)
	}
	if got := formRelayKey("192.0.2.7"); got != "192.0.2.7" {
		t.Fatalf("IPv4 key = %q", got)
	}
}

func TestClassifyFormRelayRecipients(t *testing.T) {
	own := map[string]struct{}{"site-a.example": {}}
	outside, unparsed := classifyFormRelayRecipients([]string{
		"admin@site-a.example",
		"info@news.site-a.example",
		"Victim@Outside.EXAMPLE",
	}, own)
	if unparsed {
		t.Fatal("unparsed set for valid addresses")
	}
	if want := []string{"info@news.site-a.example", "victim@outside.example"}; !reflect.DeepEqual(outside, want) {
		t.Fatalf("outside = %v, want %v", outside, want)
	}

	own["news.site-a.example"] = struct{}{}
	if outside, _ := classifyFormRelayRecipients([]string{"info@news.site-a.example"}, own); len(outside) != 0 {
		t.Fatalf("listed subdomain counted: %v", outside)
	}

	if outside, unparsed := classifyFormRelayRecipients([]string{"not an address", "v@victim.example"}, own); !unparsed || len(outside) != 1 {
		t.Fatalf("unparsable: outside=%v unparsed=%v", outside, unparsed)
	}
	// The spool parser returns no recipients when it cannot validate the
	// block, which an attacker-chosen address can cause.
	if _, unparsed := classifyFormRelayRecipients(nil, own); !unparsed {
		t.Fatal("empty recipient list not counted as unparsed")
	}
}

func TestFormRelayWindow_CountReadsWithoutChangingState(t *testing.T) {
	w := newFormRelayWindow(100)
	key := formRelayKey(formTestIP)
	formRecord(w, formTestIP, formTestA, "usera", "m1", formTestT0, false, "v1@victim.example")
	formRecord(w, formTestIP, formTestA, "usera", "m2", formTestT0.Add(time.Hour), false, "v2@victim.example")
	if got := w.count(key, formTestT0); got != 2 {
		t.Fatalf("count since t0 = %d, want 2", got)
	}
	if got := w.count(key, formTestT0.Add(time.Hour)); got != 1 {
		t.Fatalf("count since t0+1h = %d, want 1", got)
	}
	// A read far past the window must neither expire nor advance the clock.
	if got := w.count(key, formTestT0.Add(48*time.Hour)); got != 0 {
		t.Fatalf("count since t0+48h = %d, want 0", got)
	}
	if got := formRecord(w, formTestIP, formTestA, "usera", "m3", formTestT0.Add(2*time.Hour), false, "v3@victim.example"); got != 3 {
		t.Fatalf("record after reads = %d, want 3 (count must not move the window)", got)
	}
	if got := w.count(formRelayKey("192.0.2.1"), formTestT0); got != 0 {
		t.Fatalf("count of an unknown client = %d, want 0", got)
	}
	if got := w.exactIP(formRelayKey("192.0.2.1")); got != "" {
		t.Fatalf("count created a client: %q", got)
	}
}

func TestFormRelayWindow_EmptyKeyIsNeverStored(t *testing.T) {
	w := newFormRelayWindow(100)
	if got := w.record("", "", "usera", formTestA, "m1", formTestT0, []string{"v@victim.example"}, true, formTestWindow, formTestLimit); got != 0 {
		t.Fatalf("record with empty key = %d, want 0", got)
	}
	if w.markFired("", formTestT0, formTestWindow) {
		t.Fatal("empty key fired")
	}
	w.markStaff("usera", "", formTestT0)
	if w.isStaff("usera", "", formTestT0) {
		t.Fatal("empty key recorded as staff")
	}
	if len(w.ips) != 0 || len(w.staff) != 0 {
		t.Fatalf("empty key stored state: ips=%v staff=%v", w.ips, w.staff)
	}
}

// Smoke test for the race detector: each goroutine drives a different
// operation against shared keys.
func TestFormRelayWindow_ConcurrentMixedOperations(t *testing.T) {
	w := newFormRelayWindow(8)
	ips := []string{"192.0.2.1", "192.0.2.2", "198.51.100.1", "2001:db8::1", "2001:db8:0:1::1"}
	var wg sync.WaitGroup
	start := make(chan struct{})
	run := func(f func(i int)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 200; i++ {
				f(i)
			}
		}()
	}
	for g := 0; g < 3; g++ {
		run(func(i int) {
			ip := ips[(i+g)%len(ips)]
			formRecord(w, ip, formTestA, "usera", fmt.Sprintf("g%d-m%d", g, i), formTestT0.Add(time.Duration(i)*time.Minute), i%7 == 0, fmt.Sprintf("v%d@victim.example", i))
		})
	}
	run(func(i int) { w.sweep(formTestT0.Add(time.Duration(i)*time.Minute), formTestWindow) })
	run(func(i int) {
		key := formRelayKey(ips[i%len(ips)])
		w.markStaff("userb", key, formTestT0.Add(time.Duration(i)*time.Minute))
		w.isStaff("userb", key, formTestT0)
	})
	run(func(i int) {
		key := formRelayKey(ips[i%len(ips)])
		since := formTestT0.Add(-formTestWindow)
		if n := w.count(key, since); n > formTestLimit {
			t.Errorf("count = %d, above the limit %d", n, formTestLimit)
		}
		total := 0
		for _, s := range w.scriptShares(key, since) {
			total += s.Count
		}
		if total > formTestLimit {
			t.Errorf("script shares total %d, above the limit %d", total, formTestLimit)
		}
		w.markFired(key, formTestT0.Add(time.Duration(i)*time.Minute), formTestWindow)
	})
	close(start)
	wg.Wait()
	if len(w.ips) > 8 {
		t.Fatalf("table holds %d clients, cap is 8", len(w.ips))
	}
}

func TestFormRelayWindow_ScriptClaimOncePerWindow(t *testing.T) {
	w := newFormRelayWindow(100)
	if !w.claimScript(formTestA, formTestT0, formTestWindow) {
		t.Fatal("first script report not claimed")
	}
	if w.claimScript(formTestA, formTestT0.Add(23*time.Hour), formTestWindow) {
		t.Fatal("script reported twice in one window")
	}
	if !w.claimScript(formTestB, formTestT0.Add(time.Hour), formTestWindow) {
		t.Fatal("one script's report blocked another")
	}
	w.sweep(formTestT0.Add(formTestWindow+2*time.Hour), formTestWindow)
	if len(w.scriptFired) != 0 {
		t.Fatalf("sweep kept expired script reports: %v", w.scriptFired)
	}
	if !w.claimScript(formTestA, formTestT0.Add(formTestWindow+2*time.Hour), formTestWindow) {
		t.Fatal("script not reported again in the next window")
	}
}
