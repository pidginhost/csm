package webui

import (
	"bytes"
	"encoding/json"
	"testing"
)

// collectionEnvelope splits a collection response into its keys. A list
// route answers an object carrying the list under "items"; the test fails
// when the body is not a JSON object.
func collectionEnvelope(t *testing.T, body []byte) map[string]json.RawMessage {
	t.Helper()
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("collection body is not a JSON object: %v (body=%s)", err, body)
	}
	if envelope == nil {
		t.Fatalf("collection body is null, want an object with items")
	}
	return envelope
}

// decodeItems unmarshals the "items" list of a collection response into dst.
// It fails the test when items is missing or null, so an empty collection
// must arrive as [].
func decodeItems(t *testing.T, body []byte, dst any) {
	t.Helper()
	raw, ok := collectionEnvelope(t, body)["items"]
	if !ok {
		t.Fatalf("collection body has no items key: %s", body)
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		t.Fatalf("collection items is null, want a list: %s", body)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("decode items: %v (body=%s)", err, body)
	}
}

// decodeItemsTotal is decodeItems for a route that counts its matches. It
// returns the "total" key and fails the test when total is missing.
func decodeItemsTotal(t *testing.T, body []byte, dst any) int {
	t.Helper()
	decodeItems(t, body, dst)
	raw, ok := collectionEnvelope(t, body)["total"]
	if !ok {
		t.Fatalf("collection body has no total key: %s", body)
	}
	var total int
	if err := json.Unmarshal(raw, &total); err != nil {
		t.Fatalf("decode total: %v (body=%s)", err, body)
	}
	return total
}

// assertEmptyItems fails the test unless the collection response carries an
// empty, non-null items list and a total of 0.
func assertEmptyItems(t *testing.T, body []byte) {
	t.Helper()
	var items []json.RawMessage
	total := decodeItemsTotal(t, body, &items)
	if len(items) != 0 {
		t.Fatalf("items has %d entries, want an empty list: %s", len(items), body)
	}
	if total != 0 {
		t.Fatalf("total = %d, want 0: %s", total, body)
	}
}
