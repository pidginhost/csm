package checks

import (
	"strings"
	"testing"
)

// The mysql batch client returns each SHOW CREATE row as tab-joined columns
// with newlines escaped. The backup must hold the bare CREATE statement,
// unescaped, or the restore replays "trg_audit<TAB>STRICT_TRANS_TABLES<TAB>
// CREATE ..." and fails with a syntax error every time, after the object is
// already gone.
func TestDBDropObjectBackupHoldsBareCreateStatement(t *testing.T) {
	cases := []struct {
		kind string
		row  string
		want string
	}{
		{
			kind: "trigger",
			row: "trg_audit\tSTRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION\t" +
				"CREATE DEFINER=`root`@`localhost` TRIGGER `trg_audit` BEFORE INSERT ON `x` FOR EACH ROW BEGIN\\n  SET NEW.a = 1;\\nEND\t" +
				"utf8mb4\tutf8mb4_0900_ai_ci\tutf8mb4_0900_ai_ci\t2026-01-01 00:00:00.00\n",
			want: "CREATE DEFINER=`root`@`localhost` TRIGGER `trg_audit` BEFORE INSERT ON `x` FOR EACH ROW BEGIN\n  SET NEW.a = 1;\nEND",
		},
		{
			kind: "event",
			row: "ev_cleanup\tSTRICT_TRANS_TABLES\tSYSTEM\t" +
				"CREATE DEFINER=`root`@`localhost` EVENT `ev_cleanup` ON SCHEDULE EVERY 1 HOUR DO BEGIN\\n  DELETE FROM t;\\nEND\t" +
				"utf8mb4\tutf8mb4_0900_ai_ci\tutf8mb4_0900_ai_ci\n",
			want: "CREATE DEFINER=`root`@`localhost` EVENT `ev_cleanup` ON SCHEDULE EVERY 1 HOUR DO BEGIN\n  DELETE FROM t;\nEND",
		},
		{
			kind: "procedure",
			row: "sp_x\tSTRICT_TRANS_TABLES\t" +
				"CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_x`()\\nBEGIN\\n  SELECT 1;\\nEND\t" +
				"utf8mb4\tutf8mb4_0900_ai_ci\tutf8mb4_0900_ai_ci\n",
			want: "CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_x`()\nBEGIN\n  SELECT 1;\nEND",
		},
	}
	for _, c := range cases {
		t.Run(c.kind, func(t *testing.T) {
			db := withDBObjectsTempStore(t)
			withMockOS(t, &mockOSWPConfig{schema: "alice_wp"})
			withMockCmd(t, &mockCmd{
				run: func(_ string, args ...string) ([]byte, error) {
					joined := strings.Join(args, " ")
					if strings.Contains(joined, "SHOW CREATE") {
						return []byte(c.row), nil
					}
					return []byte("OK\n"), nil
				},
			})
			name := strings.SplitN(c.row, "\t", 2)[0]

			res := DBDropObject("alice", "alice_wp", c.kind, name, false)
			if !res.Success {
				t.Fatalf("drop failed: %+v", res)
			}
			backups, err := db.ListDBObjectBackups("alice")
			if err != nil || len(backups) != 1 {
				t.Fatalf("backups = %v, err = %v, want exactly one", backups, err)
			}
			if got := backups[0].CreateSQL; got != c.want {
				t.Fatalf("stored CreateSQL:\n%q\nwant:\n%q", got, c.want)
			}
		})
	}
}

// A row that does not have the columns SHOW CREATE is documented to return
// cannot be a usable backup; the drop must refuse rather than record junk.
func TestDBDropObjectRefusesUnexpectedShowCreateShape(t *testing.T) {
	withDBObjectsTempStore(t)
	withMockOS(t, &mockOSWPConfig{schema: "alice_wp"})
	dropCalled := false
	withMockCmd(t, &mockCmd{
		run: func(_ string, args ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "SHOW CREATE") {
				return []byte("trg_audit\tSTRICT_TRANS_TABLES\n"), nil
			}
			if strings.Contains(joined, "DROP") {
				dropCalled = true
			}
			return []byte("OK\n"), nil
		},
	})

	res := DBDropObject("alice", "alice_wp", "trigger", "trg_audit", false)
	if res.Success {
		t.Fatalf("drop succeeded with an unusable backup: %+v", res)
	}
	if dropCalled {
		t.Fatal("DROP was issued although no restorable backup could be captured")
	}
}
