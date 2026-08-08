package jstaint

import (
	"strings"
	"testing"

	"github.com/tdewolff/parse/v2/js"
)

// The field-sensitive fixtures below are the honesty condition for step 5: a
// coarse whole-object taint bit passes a clean corpus yet fails these. Each one
// distinguishes a tainted field from a clean sibling, or a strong update on a
// fresh object from an escaped earlier instance of the same allocation site.

func TestField_TaintedFieldThroughStringifyIsDetected(t *testing.T) {
	src := `document.onkeydown=function(e){var s={};s.lastKey=e.key;` +
		`navigator.sendBeacon("/c",JSON.stringify(s));};`
	r := firstResult(t, src)
	if r.Source != "e.key" || !strings.Contains(r.Sink, "sendBeacon") {
		t.Fatalf("got Source=%q Sink=%q, want e.key -> sendBeacon", r.Source, r.Sink)
	}
}

func TestField_QuotedFieldNameThroughStringifyIsDetected(t *testing.T) {
	src := `document.onkeydown=function(e){var s={};s["lastKey"]=e.key;` +
		`navigator.sendBeacon("/c",JSON.stringify(s));};`
	firstResult(t, src)
}

func TestField_OnlyCleanSiblingSerializedIsNotDetected(t *testing.T) {
	// lastKey is tainted, but the serialized value is a different, clean field.
	src := `document.onkeydown=function(e){var s={};s.lastKey=e.key;s.analytics={};` +
		`navigator.sendBeacon("/c",JSON.stringify(s.analytics));};`
	mustNotDetect(t, src)
}

func TestField_CleanSiblingReadIsNotDetected(t *testing.T) {
	// Reading an unrelated field of the same object must not carry the key.
	src := `document.onkeydown=function(e){var s={};s.lastKey=e.key;fetch("/c?k="+s.other);};`
	mustNotDetect(t, src)
}

func TestField_ManySiblingFieldsDoNotCrossContaminate(t *testing.T) {
	// 1,024 distinct static sibling fields, one tainted key, serialize only a
	// clean field. Field sensitivity must scale without collapsing to a bit.
	var b strings.Builder
	b.WriteString(`document.onkeydown=function(e){var s={};s.lastKey=e.key;s.analytics="ok";`)
	for i := 0; i < 1024; i++ {
		b.WriteString("s.f")
		b.WriteString(itoa(i))
		b.WriteString(`="";`)
	}
	b.WriteString(`navigator.sendBeacon("/c",JSON.stringify(s.analytics));};`)
	mustNotDetect(t, b.String())
}

func TestField_FreshObjectFieldOverwriteBeforeSerializeIsNotDetected(t *testing.T) {
	// A lone current instance is strong-updatable: a clean overwrite of the
	// tainted field before serialization clears it.
	src := `document.onkeydown=function(e){var a={};a.k=e.key;a.k="";` +
		`navigator.sendBeacon("/c",JSON.stringify(a));};`
	mustNotDetect(t, src)
}

func TestField_AliasedInstanceUnaffectedByLaterRebinding(t *testing.T) {
	// b aliases the first object. Rebinding a to a different object and clearing
	// that object's field cannot touch the earlier instance b still holds.
	src := `document.onkeydown=function(e){var a={};a.k=e.key;var b=a;a={};a.k="";` +
		`navigator.sendBeacon("/c",JSON.stringify(b));};`
	firstResult(t, src)
}

func TestField_SummaryInstanceFieldCannotBeCleared(t *testing.T) {
	// An object allocated in a loop is summarized, so its field is weak-updated: a
	// clean overwrite cannot clear taint that an escaped earlier runtime instance
	// from the same site still carries. Contrast with the lone-current-instance
	// case, where the same clean overwrite does clear the field.
	src := `document.onkeydown=function(e){var saved=[];for(var i=0;i<2;i++){` +
		`var o={};o.k=e.key;saved.push(o);o.k="";}` +
		`navigator.sendBeacon("/c",JSON.stringify(saved));};`
	firstResult(t, src)
}

func TestField_ObjectBodyWithoutSerializationIsNotDetected(t *testing.T) {
	// A plain object with a tainted nested field is not a tainted body until it
	// flows through a modeled serializer.
	src := `document.onkeydown=function(e){var s={};s.lastKey=e.key;fetch("/c",{body:s});};`
	mustNotDetect(t, src)
}

func TestField_ObjectLiteralRecordsPerField(t *testing.T) {
	// An object literal taints only the field it is written to.
	pos := `document.onkeydown=function(e){var s={lastKey:e.key};` +
		`navigator.sendBeacon("/c",JSON.stringify(s));};`
	firstResult(t, pos)

	neg := `document.onkeydown=function(e){var s={lastKey:e.key,tag:"x"};` +
		`fetch("/c?k="+s.tag);};`
	mustNotDetect(t, neg)
}

func TestField_ArrayPushJoinIsDetected(t *testing.T) {
	src := `document.onkeydown=function(e){var a=[];a.push(e.key);fetch("/c?k="+a.join(""));};`
	firstResult(t, src)
}

func TestField_ArrayIndexWriteIsDetected(t *testing.T) {
	src := `document.onkeydown=function(e){var a=[];a[0]=e.key;navigator.sendBeacon("/c",a.join(""));};`
	firstResult(t, src)
}

func TestField_WildcardWriteReadsBackTainted(t *testing.T) {
	// A write with an unresolved key taints the wildcard, so any later static
	// read of that allocation is tainted.
	src := `document.onkeydown=function(e){var s={};s[window.k]=e.key;fetch("/c?k="+s.anything);};`
	firstResult(t, src)
}

func TestField_WildcardDoesNotCrossAllocations(t *testing.T) {
	// A wildcard write on one object does not taint another object's fields.
	src := `document.onkeydown=function(e){var s={};s[window.k]=e.key;var t={};fetch("/c?k="+t.anything);};`
	mustNotDetect(t, src)
}

func TestField_DefinitelyCyclicStringifyProducesNoValue(t *testing.T) {
	// JSON.stringify on a self-referential object throws at runtime, so it yields
	// no networked value even though a field is tainted.
	src := `document.onkeydown=function(e){var o={};o.k=e.key;o.self=o;` +
		`navigator.sendBeacon("/c",JSON.stringify(o));};`
	mustNotDetect(t, src)
}

func TestField_CyclicArrayJoinTerminatesAndPropagatesOtherElements(t *testing.T) {
	// A self-referential array element contributes no taint when revisited, but a
	// separately tainted element still propagates, and analysis terminates.
	src := `document.onkeydown=function(e){var a=[];a.push(e.key);a.push(a);fetch("/c?k="+a.join(""));};`
	firstResult(t, src)
}

func TestField_AliasPreservesFieldTaint(t *testing.T) {
	// b = a copies the allocation identity, so a field tainted through b is seen
	// when a is serialized.
	src := `document.onkeydown=function(e){var a={};var b=a;b.k=e.key;` +
		`navigator.sendBeacon("/c",JSON.stringify(a));};`
	firstResult(t, src)
}

func TestField_DeepHeapChainSerializesWithoutStackOverflow(t *testing.T) {
	// A heap graph built through assignments can be far deeper than the AST. A
	// recursive serializer would overflow the Go stack, which recover cannot
	// intercept, so this proves the iterative walk both terminates and detects.
	const n = 2000
	var b strings.Builder
	b.WriteString(`document.onkeydown=function(e){`)
	for i := 0; i < n; i++ {
		b.WriteString("var o")
		b.WriteString(itoa(i))
		b.WriteString("={};")
	}
	for i := 0; i < n-1; i++ {
		b.WriteString("o")
		b.WriteString(itoa(i))
		b.WriteString(".next=o")
		b.WriteString(itoa(i + 1))
		b.WriteString(";")
	}
	b.WriteString("o")
	b.WriteString(itoa(n - 1))
	b.WriteString(".k=e.key;")
	b.WriteString(`navigator.sendBeacon("/c",JSON.stringify(o0));};`)
	firstResult(t, b.String())
}

func TestField_LoopAllocatedObjectSummarizesAndTerminates(t *testing.T) {
	// An object allocated inside a loop is summarized. The fixed point must
	// terminate, and taint captured on the summarized instance and pushed into an
	// array is detected when the array is serialized.
	src := `document.onkeydown=function(e){var buf=[];for(var i=0;i<3;i++){var o={};o.k=e.key;buf.push(o);}` +
		`navigator.sendBeacon("/c",JSON.stringify(buf));};`
	firstResult(t, src)
}

func TestPromoteCurrentMovesEveryReferenceToSummary(t *testing.T) {
	// Promotion is the recency primitive that later interprocedural steps rely on:
	// when a site is re-allocated, the earlier current instance and every reference
	// to it must move to the summary class with content preserved.
	const site = 7
	from := allocID{site: site, summary: false}
	va, vb := &js.Var{}, &js.Var{}
	other := allocID{site: 9, summary: false}

	st := newState()
	st.heap[from] = &object{fields: map[string]value{"k": {scalar: taintSet{0: nil}}}}
	st.heap[other] = &object{fields: map[string]value{"ref": {allocs: allocSet{from: true}}}}
	st.env[va] = value{allocs: allocSet{from: true}}
	st.env[vb] = value{allocs: allocSet{from: true}}

	a := &analysis{}
	a.promoteCurrent(st, site)

	to := allocID{site: site, summary: true}
	if _, ok := st.heap[from]; ok {
		t.Fatal("current instance still present after promotion")
	}
	summary, ok := st.heap[to]
	if !ok || len(summary.fields["k"].scalar) == 0 {
		t.Fatalf("summary instance missing promoted field taint: %+v", summary)
	}
	for name, v := range map[string]value{"va": st.env[va], "vb": st.env[vb]} {
		if v.allocs[from] || !v.allocs[to] {
			t.Fatalf("%s still references the current instance: %+v", name, v.allocs)
		}
	}
	if ref := st.heap[other].fields["ref"]; ref.allocs[from] || !ref.allocs[to] {
		t.Fatalf("heap field reference not rewritten: %+v", ref.allocs)
	}
}

// itoa is a tiny allocation-light integer formatter for the generated fixture.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
