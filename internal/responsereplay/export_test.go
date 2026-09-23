package responsereplay

import "reflect"

// WireFields exposes the private wire mirror to the external schema test,
// which is the only place both it and the real audit types are visible.
var WireFields = map[string]reflect.Type{
	"event":   reflect.TypeFor[wireEvent](),
	"process": reflect.TypeFor[wireProcess](),
}
