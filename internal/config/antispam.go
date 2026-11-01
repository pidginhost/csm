package config

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Check nodes before decoding: yaml.v3 coerces scalars to strings and drops
// null sequence entries, which would silently change the requested feeds.
func validateAntispamFeedTypes(node yaml.Node) error {
	var fields map[string]yaml.Node
	if err := node.Decode(&fields); err != nil {
		return err
	}
	if enabled, ok := fields["enabled"]; ok && !yamlNodeIsNull(&enabled) {
		if err := validateStringList(enabled, "email_protection.antispam.feeds.enabled"); err != nil {
			return err
		}
	}
	if keyFile, ok := fields["spamhaus_dqs_key_file"]; ok && !yamlNodeIsNull(&keyFile) && yamlResolvedTag(&keyFile) != "!!str" {
		return errors.New("email_protection.antispam.feeds.spamhaus_dqs_key_file must be a string")
	}
	return nil
}

// Enabling learning is consent to reading Spam mail, so only a YAML boolean
// counts; yaml.v3 would otherwise coerce values such as 1.
func validateAntispamLearningTypes(node yaml.Node) error {
	if yamlResolvedTag(&node) != "!!map" {
		return errors.New("email_protection.antispam.learning must be a mapping")
	}
	var fields map[string]yaml.Node
	if err := node.Decode(&fields); err != nil {
		return err
	}
	if enabled, ok := fields["enabled"]; ok && !yamlNodeIsNull(&enabled) && yamlResolvedTag(&enabled) != "!!bool" {
		return errors.New("email_protection.antispam.learning.enabled must be true or false")
	}
	return nil
}

// validateStringList requires a YAML sequence of strings, for the same
// reasons as validateAntispamFeedTypes.
func validateStringList(node yaml.Node, key string) error {
	if yamlResolvedTag(&node) != "!!seq" {
		return fmt.Errorf("%s must be a list of strings", key)
	}
	var items []yaml.Node
	if err := node.Decode(&items); err != nil {
		return err
	}
	for _, item := range items {
		if yamlResolvedTag(&item) != "!!str" {
			return fmt.Errorf("%s must contain only strings", key)
		}
	}
	return nil
}
