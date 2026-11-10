package checks

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func FuzzPrestaShopParameterValues(f *testing.F) {
	for _, body := range []string{
		psParamsBody(nil),
		psParamsBody(map[string]string{"database_password": `'fixture-escaped\'\\%%pass'`}),
		psParamsBody(map[string]string{"database_port": "false"}),
		psParamsBody(map[string]string{"database_name": `'fixture-unterminated`}),
		`<?php return ['parameters' => ['database_name' => 'fixture-name']];`,
		`<?php return ['parameters' => ['other' => ['database_password' => 'fixture-private']]];`,
		`<?php return ['parameters' => ['other' => '"database_name" => "fixture-private",']];`,
		"",
	} {
		f.Add(body)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > maxCMSConfigBytes {
			return
		}
		values, err := parsePrestaShopParameterValues(body)
		if err != nil {
			if !errors.Is(err, errPrestaShopCreds) || err.Error() != errPrestaShopCreds.Error() || values != nil {
				t.Fatal("parse failure exposed input or partial values")
			}
			return
		}
		for key, value := range values {
			if !slices.Contains(prestashopParamKeys, key) || !value.found {
				t.Fatal("parser returned an unrelated or absent parameter")
			}
		}
	})
}

func FuzzPrestaShopOpaqueParameterValue(f *testing.F) {
	for _, value := range []string{
		`"database_password" => "fixture-private",`,
		`'database_host' => 'db.example.test',`,
		"fixture-multiline\n'parameters' => array('database_name' => 'fixture-private'),",
		`fixture-escapes\'"\\%%`,
		"",
	} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		literal := "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace("fixture-"+value) + "'"
		body := strings.Replace(psParamsBody(nil), "'fixture-secret-mailer'", literal, 1)
		if len(body) > maxCMSConfigBytes {
			return
		}
		values, err := parsePrestaShopParameterValues(body)
		if err != nil {
			t.Fatalf("unrelated string prevented parsing: %v", err)
		}
		want := map[string]string{
			"database_host": "localhost", "database_port": "",
			"database_name": "shop_db", "database_user": "shop_user",
			"database_password": "fixture-db-pass", "database_prefix": "ps_",
		}
		if len(values) != len(want) {
			t.Fatal("unrelated string changed the set of returned parameters")
		}
		for key, expected := range want {
			if got := values[key]; !got.found || !got.quoted || got.value != expected {
				t.Fatalf("unrelated string changed %s", key)
			}
		}
	})
}
