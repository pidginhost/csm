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
	return w.record(formRelayKey(ip), cpuser, k, msgID, at, outside, unparsed, formTestWindow, formTestLimit)
}

// formPeek reads ip's window at at with a threshold of one, as the
// evaluator does, without claiming the client cooldown.
func formPeek(w *formRelayWindow, ip string, at time.Time) formRelaySnapshot {
	return w.evaluate(formRelayKey(ip), at, formTestWindow, 1, nil, false)
}

// formClaim is formPeek that claims the client cooldown.
func formClaim(w *formRelayWindow, ip string, at time.Time) bool {
	return w.evaluate(formRelayKey(ip), at, formTestWindow, 1, nil, true).FireClient
}

func TestFormRelayWindow_CountsDistinctOutsideRecipients(t *testing.T) {
	w := newFormRelayWindow(100)
	formRecord(w, formTestIP, formTestA, "usera", "m1", formTestT0, false, "v1@victim.example")
	formRecord(w, formTestIP, formTestB, "userb", "m2", formTestT0.Add(time.Hour), false, "v2@victim.example")
	if got := formRecord(w, formTestIP, formTestA, "usera", "m3", formTestT0.Add(2*time.Hour), false, "v3@victim.example"); got != 3 {
		t.Fatalf("count = %d, want 3", got)
	}
	snap := formPeek(w, formTestIP, formTestT0.Add(2*time.Hour))
	want := map[scriptKey]formRelayShare{
		formTestA: {Count: 2, CPUser: "usera", Raw: formTestA},
		formTestB: {Count: 1, CPUser: "userb", Raw: formTestB},
	}
	if snap.Count != 3 || !reflect.DeepEqual(snap.Shares, want) {
		t.Fatalf("snapshot = %+v, want 3 recipients in %v", snap, want)
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
	if snap := formPeek(w, formTestIP, formTestT0.Add(time.Minute)); snap.Count != 2 || len(snap.Domains) != 0 {
		t.Fatalf("unparsed entries leaked into domains: %+v", snap)
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
	last := formTestT0.Add(49 * time.Minute)
	if stored := formPeek(w, formTestIP, last).Domains; len(stored) != formTestLimit {
		t.Fatalf("stored %d recipients, want %d: %v", len(stored), formTestLimit, stored)
	}
	// Eviction ranks clients by last activity, which goes on past the limit.
	if got := w.ips[formRelayKey(formTestIP)].lastSeen; !got.Equal(last) {
		t.Fatalf("last-seen not updated past the limit: %v, want %v", got, last)
	}
}

func TestFormRelayWindow_RetainsRecentRecipientsAtLimit(t *testing.T) {
	for _, unparsed := range []bool{false, true} {
		t.Run(fmt.Sprintf("unparsed=%t", unparsed), func(t *testing.T) {
			w := newFormRelayWindow(100)
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
			want := map[scriptKey]formRelayShare{formTestB: {Count: formTestLimit, CPUser: "userb", Raw: formTestB}}
			if got := formPeek(w, formTestIP, now).Shares; !reflect.DeepEqual(got, want) {
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
	want := map[scriptKey]formRelayShare{formTestB: {Count: formTestLimit, CPUser: "userb", Raw: formTestB}}
	if got := formPeek(w, formTestIP, formTestT0.Add(time.Hour)).Shares; !reflect.DeepEqual(got, want) {
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
			if formClaim(w, formTestIP, formTestT0) {
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
	if got := w.record(formRelayKey(formTestIP), "usera", formTestA, "own-domain", formTestT0.Add(time.Hour), nil, false, formTestWindow, 2); got != 2 {
		t.Fatalf("count after lowering limit = %d, want 2", got)
	}
	if got := formPeek(w, formTestIP, formTestT0.Add(time.Hour)).Domains; !reflect.DeepEqual(got, []string{"d3.example", "d4.example"}) {
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
			if fired && !formClaim(w, "192.0.2.1", formTestT0) {
				t.Fatal("initial crossing did not fire")
			}
			formRecord(w, "192.0.2.2", formTestB, "userb", "recent", formTestT0.Add(23*time.Hour), false, "v@victim.example")
			now := formTestT0.Add(25 * time.Hour)
			formRecord(w, "192.0.2.3", formTestB, "userb", "new", now, false, "v@victim.example")
			if c := w.ips[formRelayKey("192.0.2.1")]; c != nil {
				t.Fatalf("expired client retained: %+v", c)
			}
			for _, ip := range []string{"192.0.2.2", "192.0.2.3"} {
				if got := formPeek(w, ip, now).Count; got != 1 {
					t.Fatalf("active client %s lost: count %d", ip, got)
				}
			}
			if w.sweep(now, formTestWindow) {
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
	now := formTestT0.Add(200 * time.Minute)
	formRecord(w, "192.0.2.1", formTestA, "usera", "new", now, false, "v@victim.example")

	if got := formPeek(w, hot, now).Count; got != formTestLimit-1 {
		t.Fatalf("near-crossing key was evicted: count %d", got)
	}
	if got := formPeek(w, "198.51.100.1", now).Count; got != 0 {
		t.Fatal("oldest single-recipient key survived")
	}
	for i := 2; i <= 99; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i)
		if formPeek(w, ip, now).Count != 1 {
			t.Fatalf("%s evicted, only one key should go", ip)
		}
	}
	if formPeek(w, "192.0.2.1", now).Count != 1 {
		t.Fatal("new key not stored")
	}
}

func TestFormRelayWindow_FullFlagAndSweep(t *testing.T) {
	w := newFormRelayWindow(2)
	formRecord(w, "192.0.2.1", formTestA, "usera", "m1", formTestT0, false, "v@victim.example")
	formRecord(w, "192.0.2.2", formTestA, "usera", "m2", formTestT0, false, "v@victim.example")
	if w.sweep(formTestT0, formTestWindow) {
		t.Fatal("full before the cap was passed")
	}
	formRecord(w, "192.0.2.3", formTestA, "usera", "m3", formTestT0, false, "v@victim.example")
	if !w.sweep(formTestT0, formTestWindow) {
		t.Fatal("sweep did not report the cap after inserting past it")
	}
	if w.sweep(formTestT0, formTestWindow) {
		t.Fatal("cap reported again without a new eviction")
	}
	w.sweep(formTestT0.Add(25*time.Hour), formTestWindow)
	if len(w.ips) != 0 {
		t.Fatalf("sweep kept %d keys whose recipients all expired", len(w.ips))
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
	// Each step mails the same victim again, so the client stays in the window.
	claim := func(at time.Time) bool {
		formRecord(w, formTestIP, formTestA, "usera", at.String(), at, false, "v@victim.example")
		return formClaim(w, formTestIP, at)
	}
	if !claim(formTestT0) {
		t.Fatal("first crossing did not fire")
	}
	if claim(formTestT0.Add(time.Hour)) {
		t.Fatal("fired twice in one window")
	}
	w.sweep(formTestT0.Add(2*time.Hour), formTestWindow)
	if claim(formTestT0.Add(3 * time.Hour)) {
		t.Fatal("sweep forgot a fired key inside its window")
	}
	if !claim(formTestT0.Add(25 * time.Hour)) {
		t.Fatal("did not fire again in the next window")
	}
}

// The evaluator peeks before it reads access logs; only the claim that
// follows may start the cooldown.
func TestFormRelayWindow_PeekDoesNotClaim(t *testing.T) {
	w := newFormRelayWindow(100)
	formRecord(w, formTestIP, formTestA, "usera", "m1", formTestT0, false, "v@victim.example")
	for i := 0; i < 2; i++ {
		if !formPeek(w, formTestIP, formTestT0).FireClient {
			t.Fatalf("peek %d: crossing client would not fire", i)
		}
	}
	if !formClaim(w, formTestIP, formTestT0) {
		t.Fatal("peeks claimed the cooldown")
	}
	if formPeek(w, formTestIP, formTestT0).FireClient || formClaim(w, formTestIP, formTestT0) {
		t.Fatal("claimed client would fire again in its window")
	}
}

func TestFormRelayWindow_ScriptShares(t *testing.T) {
	w := newFormRelayWindow(100)
	formRecord(w, formTestIP, formTestA, "usera", "m1", formTestT0, false, "v1@victim.example", "v2@victim.example")
	formRecord(w, formTestIP, formTestA, "usera", "m2", formTestT0, false, "v3@victim.example")
	formRecord(w, formTestIP, formTestB, "userb", "m3", formTestT0, false, "v4@other.example")
	snap := formPeek(w, formTestIP, formTestT0)
	want := map[scriptKey]formRelayShare{
		formTestA: {Count: 3, CPUser: "usera", Raw: formTestA},
		formTestB: {Count: 1, CPUser: "userb", Raw: formTestB},
	}
	if !reflect.DeepEqual(snap.Shares, want) {
		t.Fatalf("shares = %v, want %v", snap.Shares, want)
	}
	if !reflect.DeepEqual(snap.Domains, []string{"other.example", "victim.example"}) {
		t.Fatalf("domains = %v", snap.Domains)
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
			if formClaim(w, formTestIP, formTestT0) {
				fired.Add(1)
			}
			if w.sweep(formTestT0, formTestWindow) {
				t.Error("one client exceeded capacity")
			}
			snap := formPeek(w, formTestIP, formTestT0)
			if !reflect.DeepEqual(snap.Domains, []string{"victim.example"}) {
				t.Errorf("concurrent sweep lost recipient domains: %v", snap.Domains)
			}
			if share := snap.Shares[formTestA]; len(snap.Shares) != 1 || share.Count < 1 || share.Count > formTestLimit || share.Count != snap.Count || share.CPUser != "usera" {
				t.Errorf("invalid concurrent script shares: %+v", snap)
			}
			// Staff on another account leaves this account's evidence alone.
			w.markStaff("userb", key, formTestT0)
			if !w.isStaff("userb", key, formTestT0) {
				t.Error("concurrent sweep lost staff")
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := fired.Load(); got != 1 {
		t.Fatalf("concurrent crossings fired %d times, want 1", got)
	}
	want := map[scriptKey]formRelayShare{formTestA: {Count: formTestLimit, CPUser: "usera", Raw: formTestA}}
	if got := formPeek(w, formTestIP, formTestT0).Shares; !reflect.DeepEqual(got, want) {
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

func TestFormRelayWindow_EvaluateBelowSpreadOrUnknownChangesNothing(t *testing.T) {
	w := newFormRelayWindow(100)
	key := formRelayKey(formTestIP)
	formRecord(w, formTestIP, formTestA, "usera", "m1", formTestT0, false, "v1@victim.example")
	formRecord(w, formTestIP, formTestA, "usera", "m2", formTestT0.Add(time.Hour), false, "v2@victim.example")
	if snap := w.evaluate(key, formTestT0.Add(time.Hour), formTestWindow, 3, nil, true); snap.Count != 0 || snap.FireClient {
		t.Fatalf("below spread = %+v, want an empty snapshot", snap)
	}
	if !formClaim(w, formTestIP, formTestT0.Add(time.Hour)) {
		t.Fatal("a snapshot below spread claimed the cooldown")
	}
	if snap := formPeek(w, "192.0.2.1", formTestT0.Add(time.Hour)); snap.Count != 0 || snap.FireClient {
		t.Fatalf("unknown client = %+v, want an empty snapshot", snap)
	}
	if len(w.ips) != 1 {
		t.Fatalf("evaluate created a client: %d clients", len(w.ips))
	}
}

func TestFormRelayWindow_EmptyKeyIsNeverStored(t *testing.T) {
	w := newFormRelayWindow(100)
	if got := w.record("", "usera", formTestA, "m1", formTestT0, []string{"v@victim.example"}, true, formTestWindow, formTestLimit); got != 0 {
		t.Fatalf("record with empty key = %d, want 0", got)
	}
	if w.evaluate("", formTestT0, formTestWindow, 1, nil, true).FireClient {
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
		snap := w.evaluate(key, formTestT0.Add(time.Duration(i)*time.Minute), formTestWindow, 1, nil, i%2 == 0)
		if snap.Count > formTestLimit {
			t.Errorf("count = %d, above the limit %d", snap.Count, formTestLimit)
		}
		total := 0
		for _, s := range snap.Shares {
			total += s.Count
		}
		if total != snap.Count {
			t.Errorf("script shares total %d, count %d", total, snap.Count)
		}
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
