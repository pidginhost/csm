package checks

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPrestaShopCredsPreserveQueryIdentity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := new(dbQueryState)
	creds := prestashopCreds{
		ctx: ctx, queryState: state,
		dbName: "fixture-db", dbUser: "fixture-user", dbPass: "fixture-pass",
		dbHost: "db.example.test:3307", dbPrefix: "fixture_",
	}
	got := creds.asWPDBCreds()
	want := wpDBCreds{
		dbName: "fixture-db", dbUser: "fixture-user", dbPass: "fixture-pass",
		dbHost: "db.example.test:3307", tablePrefix: "fixture_",
		queryCtx: ctx, queryOwner: "db_content_prestashop", queryState: state,
	}
	if got != want {
		t.Fatal("database adapter changed credentials, owner, context, or shared query state")
	}
	cancel()
	if !errors.Is(got.queryCtx.Err(), context.Canceled) {
		t.Fatal("database queries did not inherit cancellation")
	}
}

func TestPrestaShopParametersKeepValuesOpaque(t *testing.T) {
	for _, key := range prestashopParamKeys {
		t.Run(key, func(t *testing.T) {
			// This is valid var_export output: double quotes inside a
			// single-quoted value do not need escaping.
			decoy := `'fixture-text "` + key + `" => "/fixture-foreign", fixture-tail'`
			body := strings.Replace(psParamsBody(nil), "'fixture-secret-mailer'", decoy, 1)
			creds, err := parsePSParamsBody(t, body)
			if err != nil {
				t.Fatalf("unrelated value affected parsing: %v", err)
			}
			if creds.dbName != "shop_db" || creds.dbUser != "shop_user" ||
				creds.dbPass != "fixture-db-pass" || creds.dbHost != "localhost" || creds.dbPrefix != "ps_" {
				t.Fatal("unrelated value replaced a database setting")
			}
		})
	}
	for _, key := range []string{"database_name", "database_user", "database_prefix"} {
		t.Run("missing_"+key, func(t *testing.T) {
			body := strings.Replace(psParamsBody(map[string]string{key: psOmit}),
				"'fixture-secret-mailer'", `'fixture-text "`+key+`" => "fixture_foreign", fixture-tail'`, 1)
			assertPrestaShopParametersInvalid(t, body)
		})
	}
}

func TestPrestaShopParametersRespectArrayScope(t *testing.T) {
	for _, extra := range []string{
		`'mailer_options' => array('database_password' => 'fixture-foreign'),`,
		`'mailer_options' => ['database_password' => 'fixture-foreign'],`,
		`// 'database_password' => 'fixture-foreign',`,
		`# 'database_password' => 'fixture-foreign',`,
		`/* 'database_password' => 'fixture-foreign', */`,
	} {
		body := strings.Replace(psParamsBody(nil), "  ),", "    "+extra+"\n  ),", 1)
		creds, err := parsePSParamsBody(t, body)
		if err != nil || creds.dbPass != "fixture-db-pass" {
			t.Fatalf("nested value or comment affected credentials: %v", err)
		}
	}
	body := strings.Replace(psParamsBody(nil), "\n);", "\n'database_password' => 'fixture-foreign',\n);", 1)
	creds, err := parsePSParamsBody(t, body)
	if err != nil || creds.dbPass != "fixture-db-pass" {
		t.Fatalf("outer array affected credentials: %v", err)
	}
	assertPrestaShopParametersInvalid(t, strings.Replace(psParamsBody(nil), "'parameters'", "'fixture_other'", 1))
}

func TestPrestaShopParametersLastDuplicateWins(t *testing.T) {
	body := strings.Replace(psParamsBody(nil), "  ),", "    'database_password' => 'fixture-last%%pass',\n  ),", 1)
	creds, err := parsePSParamsBody(t, body)
	if err != nil || creds.dbPass != "fixture-last%pass" {
		t.Fatalf("last duplicate did not win: %v", err)
	}
	for _, suffix := range []string{
		"    'database_password' => 'fixture-last' . 'fixture-tail',\n  ),",
		"    'database_password' => 'fixture-unterminated\n  ),",
	} {
		assertPrestaShopParametersInvalid(t, strings.Replace(psParamsBody(nil), "  ),", suffix, 1))
	}
	// PHP replaces the whole parameters array, not just the keys present
	// in the later array. Earlier required keys cannot fill the gaps.
	body = strings.Replace(psParamsBody(nil), "\n);", "\n'parameters' => ['database_password' => 'fixture-last'],\n);", 1)
	assertPrestaShopParametersInvalid(t, body)
}

func TestPrestaShopParametersRejectMalformedStructure(t *testing.T) {
	for _, body := range []string{
		strings.Replace(psParamsBody(nil), "'fixture-secret-mailer'", "'fixture-unterminated", 1),
		strings.TrimSuffix(psParamsBody(nil), "  ),\n);\n"),
		strings.Replace(psParamsBody(nil), "  ),", "  ],", 1),
		strings.Replace(psParamsBody(nil), "<?php return", "<?php $fixture =", 1),
		strings.Replace(psParamsBody(nil), "<?php return array", "<?php returnarray", 1),
		strings.Replace(psParamsBody(nil), "<?php return", "<?phpreturn", 1),
		psParamsBody(nil) + "$fixture = 'fixture-unterminated",
	} {
		assertPrestaShopParametersInvalid(t, body)
	}
}

func TestPrestaShopParametersPHPKeywords(t *testing.T) {
	body := strings.NewReplacer("return", "RETURN", "array", "ARRAY").Replace(psParamsBody(nil))
	creds, err := parsePSParamsBody(t, body)
	if err != nil || creds.dbPass != "fixture-db-pass" {
		t.Fatalf("valid PHP keywords were rejected: %v", err)
	}
}

func TestPrestaShopParametersRejectDynamicKeys(t *testing.T) {
	for _, key := range []string{`"database_\x70assword"`, `"database_\u{0070}assword"`, `"database_$fixture"`} {
		body := strings.Replace(psParamsBody(nil), "  ),", "    "+key+" => 'fixture-last',\n  ),", 1)
		assertPrestaShopParametersInvalid(t, body)
	}
}

func TestPrestaShopParametersRejectNonStringCredentials(t *testing.T) {
	for _, key := range []string{"database_host", "database_password"} {
		for _, literal := range []string{"123", "NULL", "false", "true"} {
			t.Run(key+"_"+literal, func(t *testing.T) {
				assertPrestaShopParametersInvalid(t, psParamsBody(map[string]string{key: literal}))
			})
		}
	}
}

func TestPrestaShopParametersPHPEmptyPort(t *testing.T) {
	for _, literal := range []string{"false", "FALSE", "0.0", "-0.0", "[]", "array ()", "ARRAY ()"} {
		t.Run(literal, func(t *testing.T) {
			creds, err := parsePSParamsBody(t, psParamsBody(map[string]string{"database_port": literal}))
			if err != nil || creds.dbHost != "localhost" {
				t.Fatalf("PHP-empty port was not omitted: %v", err)
			}
		})
	}
}

func TestPrestaShopParametersIntegerPortUsesPHPValue(t *testing.T) {
	for _, tc := range []struct{ literal, host string }{
		{"03307", "localhost:1735"},
		{"00", "localhost"},
		{"'03307'", "localhost:03307"},
	} {
		t.Run(tc.literal, func(t *testing.T) {
			creds, err := parsePSParamsBody(t, psParamsBody(map[string]string{"database_port": tc.literal}))
			if err != nil || creds.dbHost != tc.host {
				t.Fatalf("port differs from PHP's value: %v", err)
			}
		})
	}
}

func TestPrestaShopParametersRejectInvalidNumericPort(t *testing.T) {
	for _, literal := range []string{"09", "99999999999999999999999999", "true", "[3307]", "fal\u017fe", "0x0p0"} {
		t.Run(literal, func(t *testing.T) {
			assertPrestaShopParametersInvalid(t, psParamsBody(map[string]string{"database_port": literal}))
		})
	}
}

func assertPrestaShopParametersInvalid(t *testing.T, body string) {
	t.Helper()
	creds, err := parsePSParamsBody(t, body)
	if !errors.Is(err, errPrestaShopCreds) {
		t.Fatalf("expected invalid credentials error, got %v", err)
	}
	if creds != (prestashopCreds{}) {
		t.Fatal("invalid configuration exposed partial credentials")
	}
	if strings.Contains(err.Error(), "fixture-") {
		t.Fatal("error exposed a configuration value")
	}
}
