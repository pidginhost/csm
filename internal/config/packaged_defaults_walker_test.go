package config

import (
	"reflect"
	"testing"
)

func TestDiffConfigValuesYAMLPaths(t *testing.T) {
	type entry struct {
		Enabled bool     `yaml:"enabled"`
		Names   []string `yaml:"names"`
		Ignored string   `yaml:"-"`
	}
	type Embedded struct {
		Enabled bool `yaml:"enabled"`
	}
	type embedded struct {
		Enabled bool `yaml:"enabled"`
	}
	tests := []struct {
		name string
		a, b any
		want map[string][2]string
	}{
		{
			name: "untagged and empty tags use lowercase names",
			a: struct {
				FirstName string
				LastName  string `yaml:""`
				Optional  string `yaml:",omitempty"`
			}{},
			b: struct {
				FirstName string
				LastName  string `yaml:""`
				Optional  string `yaml:",omitempty"`
			}{"first", "last", "value"},
			want: map[string][2]string{
				"firstname": {`""`, `"first"`},
				"lastname":  {`""`, `"last"`},
				"optional":  {`""`, `"value"`},
			},
		},
		{
			name: "embedded field is nested unless inline",
			a:    struct{ Embedded }{},
			b:    struct{ Embedded }{Embedded{true}},
			want: map[string][2]string{"embedded.enabled": {"false", "true"}},
		},
		{
			name: "inline struct",
			a: struct {
				Embedded `yaml:",inline"`
			}{},
			b: struct {
				Embedded `yaml:",inline"`
			}{Embedded{true}},
			want: map[string][2]string{"enabled": {"false", "true"}},
		},
		{
			name: "unexported embedded type retains exported fields",
			a:    struct{ embedded }{},
			b:    struct{ embedded }{embedded{true}},
			want: map[string][2]string{"embedded.enabled": {"false", "true"}},
		},
		{
			name: "nil inline pointer",
			a: struct {
				*Embedded `yaml:",inline"`
			}{},
			b: struct {
				*Embedded `yaml:",inline"`
			}{&Embedded{true}},
			want: map[string][2]string{"enabled": {"null", "true"}},
		},
		{
			name: "inline map",
			a: struct {
				Extra map[string]string `yaml:",inline"`
			}{map[string]string{"mode": "before"}},
			b: struct {
				Extra map[string]string `yaml:",inline"`
			}{map[string]string{"mode": "after"}},
			want: map[string][2]string{"mode": {`"before"`, `"after"`}},
		},
		{
			name: "slice of structs has leaf paths",
			a:    []entry{{Names: []string{}}},
			b:    []entry{{Enabled: true}},
			want: map[string][2]string{"[0].enabled": {"false", "true"}},
		},
		{
			name: "map of structs has leaf paths",
			a:    map[string]entry{"first": {}},
			b:    map[string]entry{"first": {Enabled: true}},
			want: map[string][2]string{"first.enabled": {"false", "true"}},
		},
		{
			name: "ignored fields and nested empty collections",
			a:    map[string][]entry{"first": {{Ignored: "before"}}},
			b:    map[string][]entry{"first": {{Ignored: "after", Names: []string{}}}},
			want: map[string][2]string{},
		},
		{
			name: "nil pointer to struct expands leaves",
			a:    (*Embedded)(nil),
			b:    &Embedded{true},
			want: map[string][2]string{"enabled": {"null", "true"}},
		},
		{
			name: "removed pointer to struct expands leaves",
			a:    &Embedded{},
			b:    (*Embedded)(nil),
			want: map[string][2]string{"enabled": {"false", "null"}},
		},
		{
			name: "added map entry retains zero-valued leaves",
			a:    map[string]Embedded{},
			b:    map[string]Embedded{"first": {}},
			want: map[string][2]string{"first.enabled": {"null", "false"}},
		},
		{
			name: "removed slice entry retains zero-valued leaves",
			a:    []Embedded{{}},
			b:    []Embedded{},
			want: map[string][2]string{"[0].enabled": {"false", "null"}},
		},
		{
			name: "map keys cannot collide with nested paths",
			a:    map[string]Embedded{"first.second": {}, "first[0]": {}},
			b:    map[string]Embedded{"first.second": {true}, "first[0]": {true}},
			want: map[string][2]string{
				`["first.second"].enabled`: {"false", "true"},
				`["first[0]"].enabled`:     {"false", "true"},
			},
		},
		{
			name: "maps of struct pointers compare by value",
			a:    map[string]*Embedded{"first": {true}},
			b:    map[string]*Embedded{"first": {true}},
			want: map[string][2]string{},
		},
		{
			name: "slice of struct pointers has leaf paths",
			a:    []*Embedded{{true}},
			b:    []*Embedded{{false}},
			want: map[string][2]string{"[0].enabled": {"true", "false"}},
		},
		{
			name: "adding a nil struct pointer is still a new map entry",
			a:    map[string]*Embedded{},
			b:    map[string]*Embedded{"first": nil},
			want: map[string][2]string{"first": {"<absent>", "null"}},
		},
		{
			name: "removing a nil struct pointer changes slice length",
			a:    []*Embedded{nil},
			b:    []*Embedded{},
			want: map[string][2]string{"[0]": {"null", "<absent>"}},
		},
		{
			name: "nil pointer and empty struct remain distinct",
			a:    (*struct{})(nil),
			b:    &struct{}{},
			want: map[string][2]string{"": {"null", "{}"}},
		},
		{
			name: "slice values are unambiguous",
			a:    []string{"first second"},
			b:    []string{"first", "second"},
			want: map[string][2]string{"": {`["first second"]`, `["first","second"]`}},
		},
		{
			name: "map values are unambiguous",
			a:    map[string]string{"first": "value second:value"},
			b:    map[string]string{"first": "value", "second": "value"},
			want: map[string][2]string{"": {`{"first":"value second:value"}`, `{"first":"value","second":"value"}`}},
		},
		{
			name: "scalar pointers compare by value",
			a:    new(true),
			b:    new(true),
			want: map[string][2]string{},
		},
		{
			name: "empty and nil scalar collections compare equal",
			a:    []string(nil),
			b:    []string{},
			want: map[string][2]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := map[string][2]string{}
			diffConfigValues("", reflect.ValueOf(tt.a), reflect.ValueOf(tt.b), got)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("differences = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestPackagedTriStateDifferencesHaveEffects(t *testing.T) {
	for key, difference := range packagedDefaultDifferences {
		if difference.builtIn == "null" && difference.effect == nil {
			t.Errorf("%s: tri-state difference has no effective-value check", key)
		}
	}
}

func TestVerdictSignatureEffect(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value *bool
		want  bool
	}{
		{"omitted", nil, true},
		{"enabled", new(true), true},
		{"disabled", new(false), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.AutoResponse.VerdictCallback.RequireResponseSignature = tt.value
			if got := verdictSignatureEffect(t, cfg); got != tt.want {
				t.Errorf("signature required = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPackagedBPFDryRunEffect(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value *bool
		want  bool
	}{
		{"omitted", nil, true},
		{"enabled", new(true), true},
		{"disabled", new(false), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.BPFEnforcement.DryRun = tt.value
			cfg.BPFEnforcement.DirectSMTPEgress = true
			effect := packagedDefaultDifferences["bpf_enforcement.dry_run"].effect
			if got := effect(t, cfg); got != tt.want {
				t.Errorf("BPF dry run = %v, want %v; other dry-run guards must not mask this setting", got, tt.want)
			}
			if cfg.AutoResponse.DryRun != nil || cfg.Detection.DirectSMTPEgress.DryRun != nil {
				t.Error("effective-value check changed the input config")
			}
		})
	}
}
