package signatures

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRepositoryRuleSetMetadataAdvancedForNewRules(t *testing.T) {
	configsDir := filepath.Join("..", "..", "configs")
	yamlData, err := os.ReadFile(filepath.Join(configsDir, "malware.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Version int    `yaml:"version"`
		Updated string `yaml:"updated"`
	}
	if unmarshalErr := yaml.Unmarshal(yamlData, &metadata); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	if metadata.Version < 7 || metadata.Updated < "2026-08-02" {
		t.Fatalf("YAML rule-set metadata was not advanced for the new rules: version=%d updated=%q", metadata.Version, metadata.Updated)
	}

	yaraData, err := os.ReadFile(filepath.Join(configsDir, "malware.yar"))
	if err != nil {
		t.Fatal(err)
	}
	header := string(yaraData)
	versionMatch := regexp.MustCompile(`(?m)^ \* Version: ([0-9]+)$`).FindStringSubmatch(header)
	if len(versionMatch) != 2 {
		t.Fatal("YARA rule-set version is missing")
	}
	yaraVersion, err := strconv.Atoi(versionMatch[1])
	if err != nil {
		t.Fatal(err)
	}
	updatedMatch := regexp.MustCompile(`(?m)^ \* Updated: ([0-9]{4}-[0-9]{2}-[0-9]{2})$`).FindStringSubmatch(header)
	if len(updatedMatch) != 2 {
		t.Fatal("YARA rule-set update date is missing")
	}
	if yaraVersion < 6 || updatedMatch[1] < "2026-08-02" {
		t.Fatalf("YARA rule-set metadata was not advanced for the new rules: version=%d updated=%q", yaraVersion, updatedMatch[1])
	}
}
