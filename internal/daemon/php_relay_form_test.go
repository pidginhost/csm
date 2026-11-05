package daemon

import (
	"fmt"
	"reflect"
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
		"Victim@Example.COM",
	}, own)
	if unparsed {
		t.Fatal("unparsed set for valid addresses")
	}
	if want := []string{"info@news.site-a.example", "victim@example.com"}; !reflect.DeepEqual(outside, want) {
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
