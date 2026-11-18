package stalwartsetup

import (
	"reflect"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/ipmap"
)

func TestAddressListCreateUsesMaximumScore(t *testing.T) {
	original := ipmap.CINS
	t.Cleanup(func() { ipmap.CINS = original })
	ipmap.CINS.Multiplier = 0.9
	api := configuredAPI()
	api.rules, api.tags = nil, nil
	s := stepNamed(t, inspect(t, api, fieldInputs()), "address list")
	want := strings.Replace(addressListCreate, "up to 4", "up to 4.5", 1)
	if s.State != Change || s.Detail != want {
		t.Fatalf("step = %+v, want Change %q", s, want)
	}
}

func TestAddressListNonScoringTags(t *testing.T) {
	for _, kind := range []string{"Reject", "Discard", "", "unknown\x1b[31m"} {
		t.Run(kind, func(t *testing.T) {
			api := configuredAPI()
			tag := api.tags["CSM_IP_DROP"]
			tag.Type, tag.Score = kind, 9
			api.tags[tag.Tag] = tag
			p := inspect(t, api, fieldInputs())
			want := strings.Replace(addressListDone, "CSM_IP_DROP 4, ", "", 1) + "; non-scoring tags: CSM_IP_DROP"
			if s := stepNamed(t, p, "address list"); s.State != Done || s.Detail != want || !p.AddressListOn {
				t.Fatalf("step = %+v, on %v; want Done %q and the list on", s, p.AddressListOn, want)
			}
			if calls := applyCalls(t, api, p); len(calls) != 0 {
				t.Fatalf("Apply made calls %q", calls)
			}
			delete(api.tags, "CSM_IP_SPAM")
			p = inspect(t, api, fieldInputs())
			if calls := applyCalls(t, api, p); !reflect.DeepEqual(calls, []string{"CreateSpamTag(CSM_IP_SPAM,3)", "ReloadSettings"}) {
				t.Fatalf("missing tag: calls = %q", calls)
			}
			if got := api.tags[tag.Tag]; got != tag {
				t.Fatalf("operator tag = %+v, want %+v", got, tag)
			}
		})
	}
}

func TestAddressListNoScoringTags(t *testing.T) {
	api := configuredAPI()
	for name, tag := range api.tags {
		tag.Type = "Reject"
		api.tags[name] = tag
	}
	p := inspect(t, api, fieldInputs())
	want := "rule CSM_IP has no scoring tags; non-scoring tags: CSM_IP_DROP, CSM_IP_BLOCKED, CSM_IP_MAIL_AUTH, CSM_IP_SPAM, CSM_IP_BLOCKLISTDE, CSM_IP_CINS, CSM_IP_CANARY"
	if s := stepNamed(t, p, "address list"); s.State != Done || s.Detail != want {
		t.Fatalf("step = %+v, want Done %q", s, want)
	}
	if calls := applyCalls(t, api, p); len(calls) != 0 {
		t.Fatalf("Apply made calls %q", calls)
	}
}

func TestAddressListMissingTagsPlural(t *testing.T) {
	api := configuredAPI()
	delete(api.tags, "CSM_IP_SPAM")
	delete(api.tags, "CSM_IP_CINS")
	s := stepNamed(t, inspect(t, api, fieldInputs()), "address list")
	want := "create the missing tags CSM_IP_SPAM, CSM_IP_CINS"
	if s.State != Change || s.Detail != want {
		t.Fatalf("step = %+v, want Change %q", s, want)
	}
}
