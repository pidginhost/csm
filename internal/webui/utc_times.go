package webui

import (
	"errors"
	"reflect"
	"sync"
	"time"
)

// Every instant the API sends is in UTC. Stores stamp times in the host's
// zone, and older records keep whatever zone they were saved in, so the
// write path passes each response through utcTimes. It returns a copy in
// which every time.Time reachable through exported fields, pointers, slices,
// arrays, maps and interfaces is in UTC. The input is never modified: it may
// share slices and pointers with a live store, so every container on the way
// to a time is copied before anything in it changes.
//
// The copy keeps concrete types, nil versus empty containers and value
// versus pointer placement, so encoding/json renders it exactly as it would
// the original, custom marshalers included. Map keys are left alone; two
// distinct instants must not collapse into one key.

var timeType = reflect.TypeFor[time.Time]()

// errTimesTooDeep refuses a value nested past maxTimesDepth, which only a
// cycle reaches.
var errTimesTooDeep = errors.New("response nests too deep to encode")

const maxTimesDepth = 64

// holdsTimesCache records, per type, whether a value can reach a time.Time.
var holdsTimesCache sync.Map // reflect.Type -> bool

func holdsTimes(t reflect.Type) bool {
	if cached, ok := holdsTimesCache.Load(t); ok {
		return cached.(bool)
	}
	holds := holdsTimesIn(t, map[reflect.Type]bool{})
	holdsTimesCache.Store(t, holds)
	return holds
}

// holdsTimesIn answers holdsTimes for one type. A type met again during its
// own walk adds nothing its other fields do not already show, so a
// recursive type such as a process parent chain terminates.
func holdsTimesIn(t reflect.Type, seen map[reflect.Type]bool) bool {
	if t == timeType {
		return true
	}
	if seen[t] {
		return false
	}
	seen[t] = true
	switch t.Kind() {
	case reflect.Interface:
		// The dynamic value decides; an interface may hold anything.
		return true
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
		return holdsTimesIn(t.Elem(), seen)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.IsExported() && holdsTimesIn(f.Type, seen) {
				return true
			}
		}
	}
	return false
}

// utcTimes returns v with every reachable instant in UTC.
func utcTimes(v any) (any, error) {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() || !holdsTimes(rv.Type()) {
		return v, nil
	}
	out := reflect.New(rv.Type()).Elem()
	out.Set(rv)
	if err := utcInPlace(out, 0); err != nil {
		return nil, err
	}
	return out.Interface(), nil
}

// utcInPlace converts the times in v, an addressable value the caller owns.
// A pointer, slice, map or interface in v still points at shared data, so
// each is replaced by a copy before anything under it changes.
func utcInPlace(v reflect.Value, depth int) error {
	t := v.Type()
	if t == timeType {
		p := v.Addr().Interface().(*time.Time)
		*p = p.UTC()
		return nil
	}
	if !holdsTimes(t) {
		return nil
	}
	if depth > maxTimesDepth {
		return errTimesTooDeep
	}
	switch t.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return nil
		}
		p := reflect.New(t.Elem())
		p.Elem().Set(v.Elem())
		if err := utcInPlace(p.Elem(), depth+1); err != nil {
			return err
		}
		v.Set(p)
	case reflect.Interface:
		if v.IsNil() {
			return nil
		}
		elem := v.Elem()
		if !holdsTimes(elem.Type()) {
			return nil
		}
		c := reflect.New(elem.Type()).Elem()
		c.Set(elem)
		if err := utcInPlace(c, depth+1); err != nil {
			return err
		}
		v.Set(c)
	case reflect.Slice:
		if v.IsNil() {
			return nil
		}
		c := reflect.MakeSlice(t, v.Len(), v.Len())
		reflect.Copy(c, v)
		for i := 0; i < c.Len(); i++ {
			if err := utcInPlace(c.Index(i), depth+1); err != nil {
				return err
			}
		}
		v.Set(c)
	case reflect.Array:
		// An array is a value; v already holds its own copy.
		for i := 0; i < v.Len(); i++ {
			if err := utcInPlace(v.Index(i), depth+1); err != nil {
				return err
			}
		}
	case reflect.Map:
		if v.IsNil() {
			return nil
		}
		c := reflect.MakeMapWithSize(t, v.Len())
		iter := v.MapRange()
		for iter.Next() {
			val := reflect.New(t.Elem()).Elem()
			val.Set(iter.Value())
			if err := utcInPlace(val, depth+1); err != nil {
				return err
			}
			c.SetMapIndex(iter.Key(), val)
		}
		v.Set(c)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() || !holdsTimes(f.Type) {
				continue
			}
			if err := utcInPlace(v.Field(i), depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
