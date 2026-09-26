package checks

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/pidginhost/csm/internal/crawlid"
)

// The crawl detector and http_asn_crawl must agree on what is expensive, or
// the two checks would describe the same traffic differently.
func TestHTTPASNCrawlExpensiveMatchesCrawlidVectors(t *testing.T) {
	raw, err := os.ReadFile("../crawlid/testdata/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf struct {
		MaxLen  int `json:"max_len"`
		Targets []struct {
			Note   string `json:"note"`
			Raw    string `json:"raw"`
			RawB64 string `json:"raw_b64"`
			MaxLen int    `json:"max_len"`
			OK     bool   `json:"ok"`
			Err    string `json:"err"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	checked, rejected := 0, 0
	for _, v := range vf.Targets {
		rawTarget := v.Raw
		if v.RawB64 != "" {
			decoded, decodeErr := base64.RawURLEncoding.DecodeString(v.RawB64)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			rawTarget = string(decoded)
		}
		// A form the identity cannot represent must not be counted either;
		// the legacy parser has its own length bound, so skip bound rows.
		if !v.OK {
			if v.Err == "too-long" {
				continue
			}
			for _, m := range []string{"GET", "HEAD"} {
				if httpASNCrawlExpensive(accessLogRecord{Method: m, URI: rawTarget}) {
					t.Errorf("%s %s: unsupported target counted as expensive", m, v.Raw)
				}
			}
			rejected++
			continue
		}
		limit := vf.MaxLen
		if v.MaxLen != 0 {
			limit = v.MaxLen
		}
		tg, err := crawlid.ParseTarget(rawTarget, limit)
		if err != nil {
			t.Fatalf("%s: %v", v.Note, err)
		}
		for _, m := range []string{"GET", "HEAD", "POST", "PUT", "get", "OPTIONS", ""} {
			want := crawlid.Classify(m, tg).Expensive
			got := httpASNCrawlExpensive(accessLogRecord{Method: m, URI: rawTarget})
			if got != want {
				t.Errorf("%s %s: httpASNCrawlExpensive=%v crawlid=%v", m, v.Raw, got, want)
			}
			checked++
		}
	}
	valid := 0
	for _, v := range vf.Targets {
		if v.OK {
			valid++
		}
	}
	if valid == 0 || checked != valid*7 || rejected == 0 {
		t.Fatalf("checked %d method/target pairs, want %d; %d rejected rows", checked, valid*7, rejected)
	}
}

func TestHTTPASNCrawlUsesCrawlidStaticList(t *testing.T) {
	if reflect.ValueOf(httpASNCrawlStaticExts).Pointer() != reflect.ValueOf(crawlid.StaticExtensions).Pointer() {
		t.Fatal("http_asn_crawl must use crawlid.StaticExtensions, not a copy")
	}
}
