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

func TestField_ForOfSeesElementsAddedByEarlierIterations(t *testing.T) {
	src := `document.onkeydown=function(e){var a=[""];for(const ch of a){` +
		`a.push(e.key);fetch("/c?k="+ch);}};`
	firstResult(t, src)
}

func TestField_ForOfDoesNotTreatObjectNumericFieldsAsArrayElements(t *testing.T) {
	src := `document.onkeydown=function(e){var o={0:e.key};` +
		`for(const value of o){fetch("/c?k="+value);}};`
	mustNotDetect(t, src)
}

func TestField_ForOfAssignsElementToMemberTarget(t *testing.T) {
	src := `document.onkeydown=function(e){var values=[e.key];var out={};` +
		`for(out.k of values){}navigator.sendBeacon("/c",JSON.stringify(out));};`
	firstResult(t, src)
}

func TestField_ArrayIndexWriteIsDetected(t *testing.T) {
	src := `document.onkeydown=function(e){var a=[];a[0]=e.key;navigator.sendBeacon("/c",a.join(""));};`
	firstResult(t, src)
}

func TestField_ArrayIndexStrongOverwriteClearsElement(t *testing.T) {
	src := `document.onkeydown=function(e){var a=[e.key];a[0]="";` +
		`navigator.sendBeacon("/c",JSON.stringify(a));};`
	mustNotDetect(t, src)
}

func TestField_ArraySpreadNumericPropertyCanBeRead(t *testing.T) {
	src := `document.onkeydown=function(e){var a=[e.key];var out={...a};` +
		`fetch("/c?k="+out[0]);};`
	firstResult(t, src)
}

func TestField_NegativeArrayPropertyIsNotSerialized(t *testing.T) {
	src := `document.onkeydown=function(e){var a=[];a[-1]=e.key;` +
		`navigator.sendBeacon("/c",JSON.stringify(a));};`
	mustNotDetect(t, src)
}

func TestField_NewArrayArgumentsReachJoin(t *testing.T) {
	src := `document.onkeydown=function(e){var a=new Array(e.key);` +
		`fetch("/c?k="+a.join(""));};`
	firstResult(t, src)
}

func TestField_WildcardWriteReadsBackTainted(t *testing.T) {
	// A write with an unresolved key taints the wildcard, so any later static
	// read of that allocation is tainted.
	src := `document.onkeydown=function(e){var s={};s[window.k]=e.key;fetch("/c?k="+s.anything);};`
	firstResult(t, src)
}

func TestField_WildcardReadIncludesNamedFields(t *testing.T) {
	// An unresolved read can select any named property, including the tainted one.
	src := `document.onkeydown=function(e){var s={};s.secret=e.key;` +
		`fetch("/c?k="+s[window.k]);};`
	firstResult(t, src)
}

func TestField_StrongNamedWriteOverridesEarlierWildcard(t *testing.T) {
	// Whatever property the unresolved write selected, the later definite write
	// leaves k clean.
	src := `document.onkeydown=function(e){var s={};s[window.k]=e.key;s.k="";` +
		`fetch("/c?k="+s.k);};`
	mustNotDetect(t, src)
}

func TestField_CompoundAssignmentReadsFieldBeforeRHS(t *testing.T) {
	src := `document.onkeydown=function(e){var o={k:e.key};` +
		`o.k+=(o.k="");fetch("/c?k="+o.k);};`
	firstResult(t, src)
}

func TestField_LogicalAssignmentStrongUpdatesTakenPath(t *testing.T) {
	src := `document.onkeydown=function(e){var o={k:""};` +
		`o.k||=(o.k=e.key,"");fetch("/c?k="+o.k);};`
	mustNotDetect(t, src)
}

func TestField_DeleteCurrentNamedFieldClearsTaint(t *testing.T) {
	src := `document.onkeydown=function(e){var o={k:e.key};delete o.k;` +
		`navigator.sendBeacon("/c",JSON.stringify(o));};`
	mustNotDetect(t, src)
}

func TestField_DeleteThroughAliasUpdatesCurrentObject(t *testing.T) {
	src := `document.onkeydown=function(e){var o={k:e.key};var alias=o;delete alias.k;` +
		`navigator.sendBeacon("/c",JSON.stringify(o));};`
	mustNotDetect(t, src)
}

func TestField_DeleteThroughAmbiguousReceiverStaysWeak(t *testing.T) {
	src := `document.onkeydown=function(e){var tainted={k:e.key};var clean={};` +
		`var recv=window.p?tainted:clean;delete recv.k;` +
		`navigator.sendBeacon("/c",JSON.stringify(tainted));};`
	firstResult(t, src)
}

func TestField_DeleteKeepsNamedFieldClearAfterWildcardWrite(t *testing.T) {
	src := `document.onkeydown=function(e){var o={};o[window.k]=e.key;` +
		`o.safe="";delete o.safe;fetch("/c?k="+o.safe);};`
	mustNotDetect(t, src)
}

func TestField_DeleteKeepsSerializableWildcardAlternative(t *testing.T) {
	src := `document.onkeydown=function(e){var o={};o[window.k]=o;delete o.safe;` +
		`o.k=e.key;navigator.sendBeacon("/c",JSON.stringify(o));};`
	firstResult(t, src)
}

func TestField_UpdateReplacesCurrentAllocationFieldWithScalar(t *testing.T) {
	src := `document.onkeydown=function(e){var child={k:e.key};var holder={child:child};` +
		`holder.child++;navigator.sendBeacon("/c",JSON.stringify(holder));};`
	mustNotDetect(t, src)
}

func TestField_UpdateReplacesCurrentAllocationVariableWithScalar(t *testing.T) {
	src := `document.onkeydown=function(e){var value={k:e.key};value++;` +
		`navigator.sendBeacon("/c",JSON.stringify(value));};`
	mustNotDetect(t, src)
}

func TestField_WildcardDoesNotCrossAllocations(t *testing.T) {
	// A wildcard write on one object does not taint another object's fields.
	src := `document.onkeydown=function(e){var s={};s[window.k]=e.key;var t={};fetch("/c?k="+t.anything);};`
	mustNotDetect(t, src)
}

func TestField_StaticComputedPropertyUsesLastValue(t *testing.T) {
	mustNotDetect(t, `document.onkeydown=function(e){var s={["k"]:e.key,["k"]:""};`+
		`navigator.sendBeacon("/c",JSON.stringify(s));};`)

	firstResult(t, `document.onkeydown=function(e){var s={["k"]:"",["k"]:e.key};`+
		`navigator.sendBeacon("/c",JSON.stringify(s));};`)
}

func TestField_NamedObjectPropertyUsesLastValue(t *testing.T) {
	mustNotDetect(t, `document.onkeydown=function(e){var s={k:e.key,k:""};`+
		`navigator.sendBeacon("/c",JSON.stringify(s));};`)

	firstResult(t, `document.onkeydown=function(e){var s={k:"",k:e.key};`+
		`navigator.sendBeacon("/c",JSON.stringify(s));};`)
}

func TestField_NumericObjectPropertyUsesLastValue(t *testing.T) {
	mustNotDetect(t, `document.onkeydown=function(e){var s={0:e.key,0:""};`+
		`navigator.sendBeacon("/c",JSON.stringify(s));};`)

	firstResult(t, `document.onkeydown=function(e){var s={0:"",0:e.key};`+
		`navigator.sendBeacon("/c",JSON.stringify(s));};`)
	firstResult(t, `document.onkeydown=function(e){var s={0:e.key,1:""};`+
		`navigator.sendBeacon("/c",JSON.stringify(s));};`)
}

func TestField_NonIndexNumericPropertyStaysNamed(t *testing.T) {
	firstResult(t, `document.onkeydown=function(e){var o={};o[1.5]=e.key;`+
		`fetch("/c?k="+o["1.5"]);};`)

	mustNotDetect(t, `document.onkeydown=function(e){var a=[];a[1.5]=e.key;`+
		`fetch("/c?k="+a.join(""));};`)
}

func TestField_NumericPropertyUsesJavaScriptCanonicalName(t *testing.T) {
	for _, tc := range []struct {
		numeric string
		name    string
	}{
		{numeric: `1e20`, name: `100000000000000000000`},
		{numeric: `1e-6`, name: `0.000001`},
		{numeric: `1e-7`, name: `1e-7`},
		{numeric: `9007199254740993`, name: `9007199254740992`},
		{numeric: `1n`, name: `1`},
	} {
		t.Run(tc.numeric, func(t *testing.T) {
			src := `document.onkeydown=function(e){var o={};o[` + tc.numeric + `]=e.key;` +
				`fetch("/c?k="+o["` + tc.name + `"]);};`
			firstResult(t, src)
		})
	}
}

func TestArrayIndexNameHonorsJavaScriptBoundary(t *testing.T) {
	for name, want := range map[string]bool{
		"0":          true,
		"01":         false,
		"4294967294": true,
		"4294967295": false,
	} {
		if got := isArrayIndexName(name); got != want {
			t.Errorf("isArrayIndexName(%q) = %t, want %t", name, got, want)
		}
	}
}

func TestField_ObjectSpreadUsesLastDefiniteProperty(t *testing.T) {
	mustNotDetect(t, `document.onkeydown=function(e){var clean={k:""};`+
		`var s={k:e.key,...clean};navigator.sendBeacon("/c",JSON.stringify(s));};`)

	firstResult(t, `document.onkeydown=function(e){var tainted={k:e.key};`+
		`var s={k:"",...tainted};navigator.sendBeacon("/c",JSON.stringify(s));};`)
}

func TestField_ObjectSpreadThroughDefiniteFieldUsesLastProperty(t *testing.T) {
	src := `document.onkeydown=function(e){var clean={k:""};var holder={patch:clean};` +
		`var out={k:e.key,...holder.patch};` +
		`navigator.sendBeacon("/c",JSON.stringify(out));};`
	mustNotDetect(t, src)
}

func TestField_ObjectSpreadThroughOptionalReceiverStaysWeak(t *testing.T) {
	src := `document.onkeydown=function(e){var clean={k:""};var holder={patch:clean};` +
		`var maybe=window.p?holder:null;var out={k:e.key,...maybe?.patch};` +
		`navigator.sendBeacon("/c",JSON.stringify(out));};`
	firstResult(t, src)
}

func TestField_ObjectSpreadMaybePrimitiveDoesNotClearProperty(t *testing.T) {
	src := `document.onkeydown=function(e){var clean={k:""};` +
		`var patch=window.p?clean:"";var s={k:e.key,...patch};` +
		`navigator.sendBeacon("/c",JSON.stringify(s));};`
	firstResult(t, src)
}

func TestField_ObjectSpreadPreservesDefiniteCyclicElement(t *testing.T) {
	src := `document.onkeydown=function(e){var source=[];source.push(source);` +
		`var out={...source,k:e.key};` +
		`navigator.sendBeacon("/c",JSON.stringify(out));};`
	mustNotDetect(t, src)
}

func TestField_ObjectSpreadPreservesDefiniteCyclicNamedField(t *testing.T) {
	src := `document.onkeydown=function(e){var child={};child.self=child;` +
		`var source={child:child};var out={...source,k:e.key};` +
		`navigator.sendBeacon("/c",JSON.stringify(out));};`
	mustNotDetect(t, src)
}

func TestField_LoopObjectLiteralUsesFinalDuplicateProperty(t *testing.T) {
	src := `document.onkeydown=function(e){var saved=[];for(var i=0;i<2;i++){` +
		`var o={k:e.key,k:""};saved.push(o);}` +
		`navigator.sendBeacon("/c",JSON.stringify(saved));};`
	mustNotDetect(t, src)
}

func TestField_StringArrayIndexMatchesNumericElement(t *testing.T) {
	src := `document.onkeydown=function(e){var a=[];a[0]=e.key;fetch("/c?k="+a["0"]);};`
	firstResult(t, src)
}

func TestField_SyntheticElementNameDoesNotAliasNumericFields(t *testing.T) {
	src := `document.onkeydown=function(e){var o={};o["@elem"]=e.key;fetch("/c?k="+o[0]);};`
	mustNotDetect(t, src)
}

func TestField_ArraySerializersIgnoreNamedProperties(t *testing.T) {
	for _, sink := range []string{
		`fetch("/c?k="+a.join(""));`,
		`navigator.sendBeacon("/c",JSON.stringify(a));`,
	} {
		t.Run(sink, func(t *testing.T) {
			src := `document.onkeydown=function(e){var a=[];a.secret=e.key;` + sink + `};`
			mustNotDetect(t, src)
		})
	}
}

func TestField_ArrayAliasConcatDoesNotCreateScalarTaint(t *testing.T) {
	src := `document.onkeydown=function(e){var a=[];fetch(a.concat(e.key));};`
	mustNotDetect(t, src)
}

func TestField_DefinitelyCyclicStringifyProducesNoValue(t *testing.T) {
	// JSON.stringify on a self-referential object throws at runtime, so it yields
	// no networked value even though a field is tainted.
	src := `document.onkeydown=function(e){var o={};o.k=e.key;o.self=o;` +
		`navigator.sendBeacon("/c",JSON.stringify(o));};`
	mustNotDetect(t, src)
}

func TestField_DefiniteCycleThroughFieldReadProducesNoValue(t *testing.T) {
	src := `document.onkeydown=function(e){var root={k:e.key};var holder={child:root};` +
		`var child=holder.child;child.self=child;` +
		`navigator.sendBeacon("/c",JSON.stringify(root));};`
	mustNotDetect(t, src)
}

func TestField_DefiniteCycleThroughArrayIndexProducesNoValue(t *testing.T) {
	src := `document.onkeydown=function(e){var root={k:e.key};var values=[root];` +
		`var child=values[0];child.self=child;` +
		`navigator.sendBeacon("/c",JSON.stringify(root));};`
	mustNotDetect(t, src)
}

func TestField_DefiniteWildcardCycleProducesNoValue(t *testing.T) {
	src := `document.onkeydown=function(e){var root={};root.tainted=e.key;` +
		`root[window.k]=root;` +
		`navigator.sendBeacon("/c",JSON.stringify(root));};`
	mustNotDetect(t, src)
}

func TestField_DefinitelyCyclicArrayStringifyProducesNoValue(t *testing.T) {
	src := `document.onkeydown=function(e){var a=[e.key];a.push(a);` +
		`navigator.sendBeacon("/c",JSON.stringify(a));};`
	mustNotDetect(t, src)
}

func TestField_StringifySharedDiamondIsNotCyclic(t *testing.T) {
	// Reaching the same child through two siblings is convergence, not a cycle.
	src := `document.onkeydown=function(e){var shared={k:e.key};` +
		`var root={left:shared,right:shared};` +
		`navigator.sendBeacon("/c",JSON.stringify(root));};`
	firstResult(t, src)
}

func TestField_StringifyKeepsAcyclicNestedAlternative(t *testing.T) {
	// One runtime branch throws on a self-reference, but the other serializes the
	// tainted child and must remain visible to the may-flow analysis.
	src := `document.onkeydown=function(e){var child={k:e.key};var root={};` +
		`root.value=window.p?root:child;` +
		`navigator.sendBeacon("/c",JSON.stringify(root));};`
	firstResult(t, src)
}

func TestField_StringifyKeepsBranchWithoutOptionalCycle(t *testing.T) {
	src := `document.onkeydown=function(e){var root={k:e.key};` +
		`if(window.p){root.self=root;}` +
		`navigator.sendBeacon("/c",JSON.stringify(root));};`
	firstResult(t, src)
}

func TestField_StringifyKeepsPrimitiveAlternativeToCycle(t *testing.T) {
	src := `document.onkeydown=function(e){var root={k:e.key};` +
		`root.value=window.p?root:"";` +
		`navigator.sendBeacon("/c",JSON.stringify(root));};`
	firstResult(t, src)
}

func TestField_StringifyKeepsWildcardCycleOverwriteAlternative(t *testing.T) {
	src := `document.onkeydown=function(e){var root={};root[window.k]=root;` +
		`root.safe="";root.tainted=e.key;` +
		`navigator.sendBeacon("/c",JSON.stringify(root));};`
	firstResult(t, src)
}

func TestField_StringifyKeepsWeakWildcardOverwriteAlternative(t *testing.T) {
	src := `document.onkeydown=function(e){var root={k:e.key};root[window.k]=root;` +
		`var other={};var recv=window.p?root:other;recv.safe="";` +
		`navigator.sendBeacon("/c",JSON.stringify(root));};`
	firstResult(t, src)
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

func TestField_AwaitPreservesAllocationIdentity(t *testing.T) {
	src := `document.onkeydown=async function(e){var o={k:e.key};` +
		`navigator.sendBeacon("/c",JSON.stringify(await o));};`
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
