package actionlog

import "testing"

// Empty batches do not require a sink or consume writer capacity.
func TestWriteDurableEmptyBatchDoesNotCallSink(t *testing.T) {
	t.Cleanup(func() { SetSink(nil, "") })
	SetSink(nil, "")
	if err := WriteDurableBatch(nil); err != nil {
		t.Errorf("empty batch required a sink: %v", err)
	}
	SetSink(batchSinkFunc(func([]Record) error { t.Error("empty batch called sink"); return nil }), "")
	if err := WriteDurableBatch([]Record{}); err != nil {
		t.Errorf("empty batch failed: %v", err)
	}
}
