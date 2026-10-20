package learnwatch

import "testing"

func (f *stateFixture) openSub(t *testing.T, sub string, id DirIdent) (baseline, unchanged bool) {
	t.Helper()
	f.do(t, func(tx StateTx) (err error) {
		baseline, unchanged, err = tx.Open(spamKey, sub, id)
		return err
	})
	return baseline, unchanged
}

func TestFolderKeepsBothSubdirectoryIdentities(t *testing.T) {
	for _, first := range []string{"new", "cur"} {
		t.Run(first, func(t *testing.T) {
			f := newState(t)
			dirs := map[string]DirIdent{
				"cur": curDir,
				"new": {Dev: 1, Ino: 101, MtimeNs: 6, CtimeNs: 6},
			}
			second := "new"
			if first == second {
				second = "cur"
			}
			for _, sub := range []string{first, second} {
				if baseline, unchanged := f.openSub(t, sub, dirs[sub]); !baseline || unchanged {
					t.Fatalf("initial %s open: baseline=%v unchanged=%v", sub, baseline, unchanged)
				}
			}
			f.do(t, func(tx StateTx) error {
				for _, sub := range []string{first, second} {
					if err := tx.Listed(spamKey, sub, dirs[sub]); err != nil {
						return err
					}
				}
				return tx.FinishBaseline(spamKey)
			})
			for pass := 0; pass < 2; pass++ {
				for _, sub := range []string{first, second} {
					if baseline, unchanged := f.openSub(t, sub, dirs[sub]); baseline || !unchanged {
						t.Errorf("pass %d %s: baseline=%v unchanged=%v", pass, sub, baseline, unchanged)
					}
				}
			}
			if !f.observe(t, spamKey, "arrival", meta(200)) {
				t.Fatal("new arrival after both subdirectories were baselined was ignored")
			}
			f.do(t, func(tx StateTx) error { return tx.Mark(spamKey, "arrival", StatusSubmitted) })
			f.openSub(t, "cur", dirs["cur"])
			if f.observe(t, spamKey, "arrival:2,S", meta(200)) {
				t.Fatal("new-to-cur move became a second candidate")
			}
		})
	}
}

func TestReplacingSubdirectoryPreservesSiblingIdentity(t *testing.T) {
	f := newState(t)
	newDir := DirIdent{Dev: 1, Ino: 101, MtimeNs: 6, CtimeNs: 6}
	f.openSub(t, "cur", curDir)
	f.openSub(t, "new", newDir)
	f.do(t, func(tx StateTx) error {
		if err := tx.Listed(spamKey, "cur", curDir); err != nil {
			return err
		}
		if err := tx.Listed(spamKey, "new", newDir); err != nil {
			return err
		}
		return tx.FinishBaseline(spamKey)
	})

	replaced := curDir
	replaced.Ino += 2
	if baseline, unchanged := f.openSub(t, "cur", replaced); !baseline || unchanged {
		t.Fatalf("replaced open: baseline=%v unchanged=%v", baseline, unchanged)
	}
	f.do(t, func(tx StateTx) error {
		st, _, err := tx.Folder(spamKey)
		if err != nil {
			return err
		}
		if len(st.Dirs) != 2 || st.Dirs["new"].Ino != newDir.Ino {
			t.Errorf("replacement discarded sibling identity: %+v", st.Dirs)
		}
		if len(st.Listed) != 0 {
			t.Errorf("replacement retained listings from the old baseline: %+v", st.Listed)
		}
		return tx.FinishBaseline(spamKey)
	})
	if baseline, _ := f.openSub(t, "new", newDir); baseline {
		t.Fatal("unchanged sibling restarted the completed baseline")
	}
	if !f.observe(t, spamKey, "arrival", meta(201)) {
		t.Fatal("new arrival after replacement baseline was ignored")
	}
}

func TestRebaselineDoesNotRetryOldPendingEntries(t *testing.T) {
	for _, trigger := range []string{"new_subdirectory", "replacement"} {
		for _, inode := range []uint64{200, 201} {
			name := trigger + "/same_inode"
			if inode != 200 {
				name = trigger + "/different_inode"
			}
			t.Run(name, func(t *testing.T) {
				f := newState(t)
				f.baselined(t, spamKey)
				if !f.observe(t, spamKey, "pending", meta(200)) {
					t.Fatal("initial arrival was not pending")
				}
				sub := "new"
				if trigger == "replacement" {
					sub = "cur"
				}
				replaced := curDir
				replaced.Ino++
				if baseline, _ := f.openSub(t, sub, replaced); !baseline {
					t.Fatal("directory change did not start a baseline")
				}
				if f.observe(t, spamKey, "pending:2,S", meta(inode)) {
					t.Error("old pending entry bypassed the new baseline")
				}
				if e, ok := f.entry(t, spamKey, "pending"); !ok || e.Status != StatusBaseline || e.Ino != inode {
					t.Errorf("baseline entry: %+v, found=%v", e, ok)
				}
				f.do(t, func(tx StateTx) error { return tx.FinishBaseline(spamKey) })
				if f.observe(t, spamKey, "pending:2,S", meta(inode)) {
					t.Error("baseline entry was retried after baseline completion")
				}
			})
		}
	}
}
