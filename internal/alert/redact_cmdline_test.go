package alert

import "testing"

// Process findings embed /proc cmdlines in Details, and the text redaction
// only understood password= fields. A mysqldump -pSECRET argument, a
// PGPASSWORD=... environment assignment on the command line, a separated
// --password value or a URL with user:pass@ all reached alert channels and
// the finding store verbatim.
func TestRedactCommandLine(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"mysql attached -p", "mysqldump -u shop -pS3cr3t! shop_db", "mysqldump -u shop -p[REDACTED] shop_db"},
		{"mariadb attached -p", "/usr/bin/mariadb-dump -pS3cr3t --all-databases", "/usr/bin/mariadb-dump -p[REDACTED] --all-databases"},
		{"long option equals", "mysqldump --password=S3cr3t shop_db", "mysqldump --password=[REDACTED] shop_db"},
		{"long option separated", "pg_dump --password S3cr3t -h db", "pg_dump --password [REDACTED] -h db"},
		{"env assignment", "PGPASSWORD=S3cr3t pg_dump shop", "PGPASSWORD=[REDACTED] pg_dump shop"},
		{"mysql pwd env", "env MYSQL_PWD=S3cr3t mysql shop", "env MYSQL_PWD=[REDACTED] mysql shop"},
		{"sshpass", "sshpass -p S3cr3t ssh backup@203.0.113.9", "sshpass -p [REDACTED] ssh backup@203.0.113.9"},
		{"sshpass attached", "sshpass -pS3cr3t ssh backup@203.0.113.9", "sshpass -p[REDACTED] ssh backup@203.0.113.9"},
		{"curl user colon", "curl -u shop:S3cr3t https://example.com/api", "curl -u shop:[REDACTED] https://example.com/api"},
		{"curl user equals", "curl --user=shop:S3cr3t https://example.com/api", "curl --user=shop:[REDACTED] https://example.com/api"},
		{"token option", "curl --token=abcdef123456 https://example.com", "curl --token=[REDACTED] https://example.com"},
		{"api key env", "API_KEY=abcdef123456 ./sync", "API_KEY=[REDACTED] ./sync"},
		{"camelcase token env", "authToken=abcdef123456 ./sync", "authToken=[REDACTED] ./sync"},
		{"joined secret env", "CLIENTSECRET=abcdef123456 ./sync", "CLIENTSECRET=[REDACTED] ./sync"},
		{"url userinfo", "wget https://shop:S3cr3t@example.com/dump.sql", "wget https://shop:[REDACTED]@example.com/dump.sql"},
		{"url authority is not an assignment", "curl https://shop:fixture@token=0", "curl https://shop:[REDACTED]@token=0"},
		{"secret URL assignment", "API_KEY=https://example.com/fixture", "API_KEY=[REDACTED]"},
		{"url token query", "curl https://example.com/hook?token=abcdef&x=1", "curl https://example.com/hook?token=[REDACTED]&x=1"},
		{"ssh port untouched", "ssh -p 2222 backup@203.0.113.9", "ssh -p 2222 backup@203.0.113.9"},
		{"ssh attached port untouched", "ssh -p2222 backup@203.0.113.9", "ssh -p2222 backup@203.0.113.9"},
		{"mysql capital P port untouched", "mysql -P 3306 -h db shop", "mysql -P 3306 -h db shop"},
		{"mysql quoted attached password", `mysql -p'S3 cr3t' shop`, "mysql -p[REDACTED] shop"},
		{"quoted mysql executable", `"/usr/bin/mysql" -pS3cr3t shop`, `"/usr/bin/mysql" -p[REDACTED] shop`},
		{"quoted long option value", `pg_dump --password="S3 cr3t" shop`, "pg_dump --password=[REDACTED] shop"},
		{"proc argv preserves spaces", "pg_dump\x00--password=S3 cr3t\x00shop\x00", "pg_dump --password=[REDACTED] shop"},
		{"proc separated value preserves spaces", "pg_dump\x00--password\x00S3 cr3t\x00shop\x00", "pg_dump --password [REDACTED] shop"},
		{"proc shell command argument", "sh\x00-c\x00mysql -pS3cr3t shop\x00", "sh -c mysql -p[REDACTED] shop"},
		{"git author untouched", "git commit --author=Alice", "git commit --author=Alice"},
		{"ordinary tokenize option untouched", "tool --tokenize=words", "tool --tokenize=words"},
		{"ordinary pass-through option untouched", "tool --pass-through=data", "tool --pass-through=data"},
		{"ordinary secretary option untouched", "tool --secretary=alice", "tool --secretary=alice"},
		{"php process untouched", "php-fpm: pool shop", "php-fpm: pool shop"},
		{"empty", "", ""},
		{"trailing separated flag", "mysql --password", "mysql --password"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RedactCommandLine(tc.in); got != tc.want {
				t.Fatalf("RedactCommandLine(%q)\n got %q\nwant %q", tc.in, got, tc.want)
			}
			if got := RedactCommandLine(tc.want); got != tc.want {
				t.Fatalf("redacting sanitized command changed it: got %q, want %q", got, tc.want)
			}
		})
	}
}

// The text redaction used for alert bodies picks up the command-line rules
// too, so log excerpts that quote a command are covered as well.
func TestRedactSensitiveCoversCommandLineSecrets(t *testing.T) {
	in := "cmdline: mysqldump -pS3cr3t shop_db"
	if got := redactSensitive(in); got != "cmdline: mysqldump -p[REDACTED] shop_db" {
		t.Fatalf("redactSensitive(%q) = %q", in, got)
	}
}
