package config

import (
	"errors"

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
		if yamlResolvedTag(&enabled) != "!!seq" {
			return errors.New("email_protection.antispam.feeds.enabled must be a list of strings")
		}
		var names []yaml.Node
		if err := enabled.Decode(&names); err != nil {
			return err
		}
		for _, name := range names {
			if yamlResolvedTag(&name) != "!!str" {
				return errors.New("email_protection.antispam.feeds.enabled must contain only strings")
			}
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
