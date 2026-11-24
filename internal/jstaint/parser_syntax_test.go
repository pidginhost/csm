package jstaint

import (
	"strings"
	"testing"
)

// These syntax forms must preserve data flow, not merely parse successfully.
func TestAnalyze_ParserSyntaxPreservesFlows(t *testing.T) {
	cases := map[string]string{
		"import attributes": `import config from "./config.json" with {type: "json"};
document.onkeydown=function(e){fetch("/c",{body:VALUE});};`,
		"export attributes": `export {default as config} from "./config.json" with {type: "json"};
document.onkeydown=function(e){fetch("/c",{body:VALUE});};`,
		"semicolon after newline": `document.onkeydown=function(e){
var value="";if(window.enabled)value=VALUE
;else value="";fetch("/c",{body:value});};`,
		"arrow object default": `document.onkeydown=function(e){
var read=({key}={key:VALUE})=>key;fetch("/c",{body:read()});};`,
		"arrow nested default": `document.onkeydown=function(e){
var read=({nested:{key}={key:VALUE}})=>key;fetch("/c",{body:read({})});};`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				name  string
				value string
				flows int
			}{
				{"keystroke", "e.key", 1},
				{"constant", `"fixed"`, 0},
			} {
				t.Run(tc.name, func(t *testing.T) {
					got := analyzeSrc(t, strings.ReplaceAll(src, "VALUE", tc.value))
					if got.TotalResults != tc.flows || len(got.Results) != tc.flows {
						t.Fatalf("report = %+v, want %d flows", got, tc.flows)
					}
					if tc.flows == 1 && (got.Results[0].Source != "e.key" || got.Results[0].Sink != sinkFetchBody) {
						t.Errorf("result = %+v, want e.key reaching fetch body", got.Results[0])
					}
				})
			}
		})
	}
}
