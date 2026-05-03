package config

import (
	"reflect"
	"strings"
)

// Schema returns a JSON Schema (draft-07-style, partial) describing the
// Config struct via reflection over yaml: tags. Used by phpanel's config
// editor for client-side validation. Not a complete spec implementation -
// covers types, required-ness via "yaml:..." tag, and nested objects.
//
// IMPORTANT: This schema is structural only. Imperative validation rules
// enforced by Validate() (e.g., mail_logs.source must be auto/file/journal,
// webui.tokens[].scope must be admin or read) are NOT encoded here.
// Phpanel must still call `csm validate` for the authoritative check.
func Schema() map[string]interface{} {
	return reflectStruct(reflect.TypeOf(Config{}))
}

func reflectStruct(t reflect.Type) map[string]interface{} {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return map[string]interface{}{"type": "object"}
	}
	props := map[string]interface{}{}
	required := []string{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}
		name, opts := splitYAMLTag(tag)
		if name == "" {
			continue
		}
		props[name] = reflectField(f.Type)
		if !schemaContains(opts, "omitempty") && f.Type.Kind() != reflect.Pointer {
			required = append(required, name)
		}
	}
	out := map[string]interface{}{
		"type":       "object",
		"properties": props,
	}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

func reflectField(t reflect.Type) map[string]interface{} {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.String:
		return map[string]interface{}{"type": "string"}
	case reflect.Bool:
		return map[string]interface{}{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]interface{}{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]interface{}{"type": "number"}
	case reflect.Slice, reflect.Array:
		return map[string]interface{}{"type": "array", "items": reflectField(t.Elem())}
	case reflect.Map:
		return map[string]interface{}{"type": "object", "additionalProperties": reflectField(t.Elem())}
	case reflect.Struct:
		return reflectStruct(t)
	default:
		return map[string]interface{}{}
	}
}

func splitYAMLTag(tag string) (string, []string) {
	parts := strings.Split(tag, ",")
	return parts[0], parts[1:]
}

func schemaContains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
