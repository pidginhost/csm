package admission

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// These v1 bodies are fixed baseline bytes, independent of the new
// structs. Their checksums and decoded values must stay unchanged.
func TestEffectRecordAndIntentKeepVersionOneBytes(t *testing.T) {
	action := ActionID("act_00000000000000000000000000000001")
	e := EffectRecord{Action: action, Target: mustAddr(t, "192.0.2.10"), Partition: PartitionGeneral, Lane: LaneGeneral,
		Tier: Tier{Class: ClassC2, Severity: SeverityHigh}, Scope: "host/address", ExpiresAt: time.Unix(1, 0).UTC()}
	body := `{"v":1,"target":"ip:192.0.2.10","partition":1,"lane":1,"class":2,"severity":2,"scope":"host/address"}`
	want, err := sealRecord(json.RawMessage(body))
	if err != nil {
		t.Fatal(err)
	}
	data, err := e.MarshalBinary()
	key, keyErr := e.Key()
	back, decodeErr := UnmarshalEffectRecord(key, want)
	if err != nil || keyErr != nil || decodeErr != nil || back != e || !bytes.Equal(data, want) {
		t.Fatalf("v1 effect changed: %v %v %v", err, keyErr, decodeErr)
	}
	in := Intent{Action: action, Batch: "bat_00000000000000000000000000000001", Kind: KindBlockIP, Target: e.Target, ExpiresAt: e.ExpiresAt}
	body = `{"v":1,"action":"act_00000000000000000000000000000001","batch":"bat_00000000000000000000000000000001","kind":1,"target":"ip:192.0.2.10","expires_at":1000000000}`
	want, err = sealRecord(json.RawMessage(body))
	if err != nil {
		t.Fatal(err)
	}
	data, err = in.MarshalBinary()
	decoded, decodeErr := UnmarshalIntent(want)
	if err != nil || decodeErr != nil || decoded != in || !bytes.Equal(data, want) {
		t.Fatalf("v1 intent changed: %v %v", err, decodeErr)
	}
}
