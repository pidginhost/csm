package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	bolt "go.etcd.io/bbolt"
)

// All os.Open / os.ReadFile calls below take paths derived from the
// operator-configured statePath (root-owned /opt/csm or /var/lib/csm
// by default) joined with fixed filenames. gosec G304 suppressions on
// each line refer back to this package-level trust model.
func (db *DB) runMigration(statePath string) error {
	fmt.Fprintf(os.Stderr, "store: migrating flat files to bbolt...\n")

	var errs []string

	if err := db.migrateHistory(statePath); err != nil {
		errs = append(errs, fmt.Sprintf("history: %v", err))
	}
	if err := db.migrateAttackDB(statePath); err != nil {
		errs = append(errs, fmt.Sprintf("attackdb: %v", err))
	}
	if err := db.migrateThreatDB(statePath); err != nil {
		errs = append(errs, fmt.Sprintf("threatdb: %v", err))
	}
	if err := db.migrateFirewall(statePath); err != nil {
		errs = append(errs, fmt.Sprintf("firewall: %v", err))
	}
	if err := db.migrateReputation(statePath); err != nil {
		errs = append(errs, fmt.Sprintf("reputation: %v", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("partial migration: %s", strings.Join(errs, "; "))
	}

	_ = db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("meta")).Put([]byte("migrated"), []byte(time.Now().Format(time.RFC3339)))
	})

	fmt.Fprintf(os.Stderr, "store: migration complete\n")
	return nil
}

func (db *DB) migrateHistory(statePath string) error {
	path := filepath.Join(statePath, "history.jsonl")
	if _, err := os.Stat(path); err != nil {
		return nil
	}

	// #nosec G304 -- see runMigration trust note.
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var findings []alert.Finding
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		var finding alert.Finding
		if err := json.Unmarshal(scanner.Bytes(), &finding); err != nil {
			continue
		}
		findings = append(findings, finding)
	}

	if len(findings) > 0 {
		if err := db.AppendHistory(findings); err != nil {
			return err
		}
	}

	renameToBackup(path)
	fmt.Fprintf(os.Stderr, "store: migrated %d history entries\n", len(findings))
	return nil
}

func (db *DB) migrateAttackDB(statePath string) error {
	dbDir := filepath.Join(statePath, "attack_db")

	// records.json
	recordsPath := filepath.Join(dbDir, "records.json")
	if _, err := os.Stat(recordsPath); err == nil {
		// #nosec G304 -- see runMigration trust note.
		data, err := os.ReadFile(recordsPath)
		if err != nil {
			return err
		}
		var records map[string]*IPRecord
		if err := json.Unmarshal(data, &records); err != nil {
			return err
		}
		for _, r := range records {
			if err := db.SaveIPRecord(*r); err != nil {
				return err
			}
		}
		renameToBackup(recordsPath)
		fmt.Fprintf(os.Stderr, "store: migrated %d attack records\n", len(records))
	}

	// events.jsonl
	eventsPath := filepath.Join(dbDir, "events.jsonl")
	if _, err := os.Stat(eventsPath); err == nil {
		// #nosec G304 -- see runMigration trust note.
		f, err := os.Open(eventsPath)
		if err != nil {
			return err
		}
		defer f.Close()

		counter := 0
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			var event AttackEvent
			if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
				continue
			}
			if err := db.RecordAttackEvent(event, counter); err != nil {
				return err
			}
			counter++
		}
		renameToBackup(eventsPath)
		fmt.Fprintf(os.Stderr, "store: migrated %d attack events\n", counter)
	}

	return nil
}

func (db *DB) migrateThreatDB(statePath string) error {
	dbDir := filepath.Join(statePath, "threat_db")

	// permanent.txt
	permPath := filepath.Join(dbDir, "permanent.txt")
	if _, err := os.Stat(permPath); err == nil {
		// #nosec G304 -- see runMigration trust note.
		data, err := os.ReadFile(permPath)
		if err != nil {
			return err
		}
		count := 0
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, " # ", 2)
			ip := strings.TrimSpace(parts[0])
			reason := ""
			if len(parts) > 1 {
				reason = strings.TrimSpace(parts[1])
			}
			if ip != "" {
				if err := db.AddPermanentBlock(ip, reason); err != nil {
					return err
				}
				count++
			}
		}
		renameToBackup(permPath)
		fmt.Fprintf(os.Stderr, "store: migrated %d permanent blocks\n", count)
	}

	// whitelist.txt
	wlPath := filepath.Join(dbDir, "whitelist.txt")
	if _, err := os.Stat(wlPath); err == nil {
		// #nosec G304 -- see runMigration trust note.
		data, err := os.ReadFile(wlPath)
		if err != nil {
			return err
		}
		count := 0
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			ip := parts[0]
			permanent := true
			var expiresAt time.Time
			for _, p := range parts[1:] {
				if strings.HasPrefix(p, "expires=") {
					t, err := time.Parse(time.RFC3339, strings.TrimPrefix(p, "expires="))
					if err == nil {
						expiresAt = t
						permanent = false
					}
				}
				if p == "permanent" {
					permanent = true
				}
			}
			if err := db.AddWhitelistEntry(ip, expiresAt, permanent); err != nil {
				return err
			}
			count++
		}
		renameToBackup(wlPath)
		fmt.Fprintf(os.Stderr, "store: migrated %d whitelist entries\n", count)
	}

	return nil
}

func (db *DB) migrateFirewall(statePath string) error {
	path := filepath.Join(statePath, "firewall", "state.json")
	if _, serr := os.Stat(path); serr != nil {
		return nil //nolint:nilerr // file does not exist, skip migration
	}

	// #nosec G304 -- see runMigration trust note.
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	type rawBlocked struct {
		IP        string    `json:"ip"`
		Reason    string    `json:"reason"`
		BlockedAt time.Time `json:"blocked_at"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	type rawAllowed struct {
		IP        string    `json:"ip"`
		Reason    string    `json:"reason"`
		Port      int       `json:"port,omitempty"`
		ExpiresAt time.Time `json:"expires_at,omitempty"`
	}
	type rawSubnet struct {
		CIDR      string    `json:"cidr"`
		Reason    string    `json:"reason"`
		BlockedAt time.Time `json:"blocked_at"`
	}
	type rawPortAllow struct {
		IP     string `json:"ip"`
		Port   int    `json:"port"`
		Proto  string `json:"proto"`
		Reason string `json:"reason"`
	}
	type rawState struct {
		Blocked     []rawBlocked   `json:"blocked"`
		BlockedNet  []rawSubnet    `json:"blocked_nets"`
		Allowed     []rawAllowed   `json:"allowed"`
		PortAllowed []rawPortAllow `json:"port_allowed"`
	}

	var state rawState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	for _, b := range state.Blocked {
		if err := db.BlockIP(b.IP, b.Reason, b.ExpiresAt); err != nil {
			return err
		}
	}
	for _, a := range state.Allowed {
		if err := db.AllowIP(a.IP, a.Reason, a.ExpiresAt); err != nil {
			return err
		}
	}
	for _, s := range state.BlockedNet {
		if err := db.AddSubnet(s.CIDR, s.Reason); err != nil {
			return err
		}
	}
	for _, p := range state.PortAllowed {
		if err := db.AddPortAllow(p.IP, p.Port, p.Proto, p.Reason); err != nil {
			return err
		}
	}

	renameToBackup(path)
	fmt.Fprintf(os.Stderr, "store: migrated firewall state (%d blocked, %d allowed, %d subnets, %d port allows)\n",
		len(state.Blocked), len(state.Allowed), len(state.BlockedNet), len(state.PortAllowed))
	return nil
}

func (db *DB) migrateReputation(statePath string) error {
	path := filepath.Join(statePath, "reputation_cache.json")
	if _, serr := os.Stat(path); serr != nil {
		return nil //nolint:nilerr // file does not exist, skip migration
	}

	// #nosec G304 -- see runMigration trust note.
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	type rawCache struct {
		Entries map[string]*ReputationEntry `json:"entries"`
	}
	var cache rawCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return err
	}

	count := 0
	for ip, entry := range cache.Entries {
		if err := db.SetReputation(ip, *entry); err != nil {
			return err
		}
		count++
	}

	renameToBackup(path)
	fmt.Fprintf(os.Stderr, "store: migrated %d reputation entries\n", count)
	return nil
}

func renameToBackup(path string) {
	_ = os.Rename(path, path+".bak")
}
