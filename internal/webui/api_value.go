package webui

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"
)

// apiValue returns a response the way the API sends it:
//
//   - every instant is in UTC. Stores stamp times in the host's zone, and
//     older records keep whatever zone they were saved in.
//   - an empty list is [] and an empty map {}, never null. A nil pointer
//     still means "unknown" and stays null; byte slices and raw JSON keep
//     their own encoding.
//
// It works on a copy reached through exported fields, pointers, slices,
// arrays, maps and interfaces. The input is never modified: it may share
// slices and pointers with a live store, so every container on the way to
// a change is copied before anything in it changes.
//
// The copy keeps concrete types and value versus pointer placement, so
// encoding/json renders it exactly as it would the original, custom
// marshalers included. Map keys are left alone; two distinct instants must
// not collapse into one key.

var timeType = reflect.TypeFor[time.Time]()

// errResponseTooDeep refuses a value nested past maxResponseDepth, which only
// a cycle reaches.
var errResponseTooDeep = errors.New("response nests too deep to encode")

const maxResponseDepth = 64

// errUnreachableField refuses a response type that embeds an unexported
// struct holding times or lists. encoding/json promotes its fields, but
// reflection cannot set them, so they would go out unconverted.
var errUnreachableField = errors.New("response type embeds an unexported struct apiValue cannot reach")

// normalizeCache records, per type, whether apiValue may change a value of
// it: it can reach a time.Time, a list or a map.
var normalizeCache sync.Map // reflect.Type -> bool

// emptySlices holds one empty slice per type. A slice with no capacity
// shares no storage, so every response can use the same one.
var emptySlices sync.Map // reflect.Type -> reflect.Value

func emptySlice(t reflect.Type) reflect.Value {
	if cached, ok := emptySlices.Load(t); ok {
		return cached.(reflect.Value)
	}
	empty := reflect.MakeSlice(t, 0, 0)
	emptySlices.Store(t, empty)
	return empty
}

func needsNormalizing(t reflect.Type) bool {
	if cached, ok := normalizeCache.Load(t); ok {
		return cached.(bool)
	}
	needs := needsNormalizingIn(t, map[reflect.Type]bool{})
	normalizeCache.Store(t, needs)
	return needs
}

// needsNormalizingIn answers needsNormalizing for one type. A type met again
// during its own walk adds nothing its other fields do not already show, so
// a recursive type such as a process parent chain terminates.
func needsNormalizingIn(t reflect.Type, seen map[reflect.Type]bool) bool {
	if t == timeType {
		return true
	}
	if seen[t] {
		return false
	}
	seen[t] = true
	switch t.Kind() {
	case reflect.Interface, reflect.Map:
		// An interface may hold anything; a map may be nil.
		return true
	case reflect.Slice:
		// A byte slice is base64 or raw JSON, where nil has its own meaning.
		return t.Elem().Kind() != reflect.Uint8
	case reflect.Pointer, reflect.Array:
		return needsNormalizingIn(t.Elem(), seen)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.Tag.Get("json") == "-" && !hasJSONMarshaler(t) {
				continue
			}
			if (f.IsExported() || f.Anonymous) && needsNormalizingIn(f.Type, seen) {
				return true
			}
		}
	}
	return false
}

var jsonMarshalerType = reflect.TypeFor[json.Marshaler]()

func hasJSONMarshaler(t reflect.Type) bool {
	return t.Implements(jsonMarshalerType) || reflect.PointerTo(t).Implements(jsonMarshalerType)
}

var normalizeStructCache sync.Map // reflect.Type -> []int

// History pages repeat the same finding and process types thousands of
// times. Resolve tags and reachable fields once per type, not per row.
func normalizingFields(t reflect.Type) []int {
	if cached, ok := normalizeStructCache.Load(t); ok {
		return cached.([]int)
	}
	custom := hasJSONMarshaler(t)
	var fields []int
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if (!f.IsExported() && !f.Anonymous) || (f.Tag.Get("json") == "-" && !custom) {
			continue
		}
		if needsNormalizing(f.Type) {
			fields = append(fields, i)
		}
	}
	normalizeStructCache.Store(t, fields)
	return fields
}

func apiValue(v any) (any, error) {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() || !needsNormalizing(rv.Type()) {
		return v, nil
	}
	out := reflect.New(rv.Type()).Elem()
	out.Set(rv)
	if err := normalizeInPlace(out, 0); err != nil {
		return nil, err
	}
	return out.Interface(), nil
}

// normalizeInPlace normalizes v, an addressable value the caller owns. A
// pointer, slice, map or interface in v still points at shared data, so each
// is replaced by a copy before anything under it changes.
func normalizeInPlace(v reflect.Value, depth int) error {
	t := v.Type()
	if t == timeType {
		p := v.Addr().Interface().(*time.Time)
		*p = p.UTC()
		return nil
	}
	if !needsNormalizing(t) {
		return nil
	}
	if depth > maxResponseDepth {
		return errResponseTooDeep
	}
	switch t.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return nil
		}
		p := reflect.New(t.Elem())
		p.Elem().Set(v.Elem())
		if err := normalizeInPlace(p.Elem(), depth+1); err != nil {
			return err
		}
		v.Set(p)
	case reflect.Interface:
		if v.IsNil() {
			return nil
		}
		elem := v.Elem()
		if !needsNormalizing(elem.Type()) {
			return nil
		}
		c := reflect.New(elem.Type()).Elem()
		c.Set(elem)
		if err := normalizeInPlace(c, depth+1); err != nil {
			return err
		}
		v.Set(c)
	case reflect.Slice:
		if v.IsNil() {
			v.Set(emptySlice(t))
			return nil
		}
		if !needsNormalizing(t.Elem()) {
			return nil
		}
		c := reflect.MakeSlice(t, v.Len(), v.Len())
		reflect.Copy(c, v)
		for i := 0; i < c.Len(); i++ {
			if err := normalizeInPlace(c.Index(i), depth+1); err != nil {
				return err
			}
		}
		v.Set(c)
	case reflect.Array:
		// An array is a value; v already holds its own copy.
		for i := 0; i < v.Len(); i++ {
			if err := normalizeInPlace(v.Index(i), depth+1); err != nil {
				return err
			}
		}
	case reflect.Map:
		if v.IsNil() {
			v.Set(reflect.MakeMap(t))
			return nil
		}
		if !needsNormalizing(t.Elem()) {
			return nil
		}
		c := reflect.MakeMapWithSize(t, v.Len())
		iter := v.MapRange()
		for iter.Next() {
			val := reflect.New(t.Elem()).Elem()
			val.Set(iter.Value())
			if err := normalizeInPlace(val, depth+1); err != nil {
				return err
			}
			c.SetMapIndex(iter.Key(), val)
		}
		v.Set(c)
	case reflect.Struct:
		for _, index := range normalizingFields(t) {
			f := v.Field(index)
			if !f.CanSet() {
				return fmt.Errorf("%w: %s in %s", errUnreachableField, f.Type(), t)
			}
			if err := normalizeInPlace(f, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
