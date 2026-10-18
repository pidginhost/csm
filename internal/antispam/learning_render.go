package antispam

import (
	_ "embed"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
)

// RspamdLuaDir holds local Lua plugins rspamd loads at startup.
const RspamdLuaDir = "/etc/rspamd/lua.local.d"

// Learning files (spec 6.1). The check and worker files hold secrets.
var (
	LearningCheckPath  = path.Join(RspamdOverrideDir, "fuzzy_check.conf")
	LearningWorkerPath = path.Join(RspamdOverrideDir, "worker-fuzzy.inc")
	LearningGroupPath  = path.Join(RspamdLocalDir, "fuzzy_group.conf")
	LearningLuaPath    = path.Join(RspamdLuaDir, "csm_learning.lua")
)

// LuaManagedHeader is the first line of the Lua file CSM owns.
const LuaManagedHeader = "-- csm-managed-version: 1"

// LearningPlugin is the inspection plugin CSM installs as LearningLuaPath.
//
//go:embed learning_plugin.lua
var LearningPlugin string

// Values the learning rules and worker pin (spec 6.2, 6.3).
const (
	learningServer   = "127.0.0.1:11335"
	learningMaxScore = "18.0"
	learningGroupCap = "10.0"
	learningWeight   = "10.0"
	learningExpire   = "90d"
	// LearningFlag is the only fuzzy flag CSM maps.
	LearningFlag = 1
)

var learningPrefixPattern = regexp.MustCompile(`^csmfz_[0-9a-f]{32}$`)
var learningHashKeyPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// LearningPaths lists the learning files in write order.
func LearningPaths() []string {
	return []string{LearningCheckPath, LearningWorkerPath, LearningGroupPath, LearningLuaPath}
}

// validateLearningKeys checks every key that reaches a rendered file, so a
// quote or newline can never leave its UCL string.
func validateLearningKeys(k LearningKeys) error {
	if !learningHashKeyPattern.MatchString(k.Fuzzy.Reveal()) || !learningHashKeyPattern.MatchString(k.Shingles.Reveal()) {
		return errors.New("learning hash keys are not loaded")
	}
	if !learningPrefixPattern.MatchString(k.Prefix) {
		return errors.New("learning prefix is not loaded")
	}
	if err := k.Read.Validate(); err != nil {
		return fmt.Errorf("learning read keypair: %w", err)
	}
	if err := k.Write.Validate(); err != nil {
		return fmt.Errorf("learning write keypair: %w", err)
	}
	return nil
}

// RenderLearning returns the learning files keyed by path, or none when
// learning is off. The keys come from s.LearningKeys, which the caller loads.
func RenderLearning(s Settings) (map[string]string, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if !s.Learning {
		return map[string]string{}, nil
	}
	k := s.LearningKeys
	if err := validateLearningKeys(k); err != nil {
		return nil, err
	}
	return map[string]string{
		LearningCheckPath:  renderLearningRules(k),
		LearningWorkerPath: renderLearningWorker(k),
		LearningGroupPath: ManagedHeader + "\nmax_score = " + learningGroupCap + ";\nsymbols {\n" +
			"  CSM_FUZZY_SPAM { weight = " + learningWeight + "; }\n" +
			"  CSM_FUZZY_LEARN { weight = 0.0; }\n}\n",
		LearningLuaPath: LearningPlugin,
	}, nil
}

// renderLearningRules writes the scan rule csm and the learning rule
// csm_learn. Both share the hash keys and options, so they compute the same
// digests; only csm_learn carries the write key and only csm scores.
func renderLearningRules(k LearningKeys) string {
	common := func(b *strings.Builder) {
		fmt.Fprintf(b, "  servers = %q;\n", learningServer)
		fmt.Fprintf(b, "  fuzzy_key = %q;\n", k.Fuzzy.Reveal())
		fmt.Fprintf(b, "  fuzzy_shingles_key = %q;\n", k.Shingles.Reveal())
		fmt.Fprintf(b, "  read_encryption_key = %q;\n", k.Read.Public)
		b.WriteString("  skip_unknown = true;\n")
		b.WriteString("  max_score = " + learningMaxScore + ";\n")
		fmt.Fprintf(b, "  min_length = %d;\n", LearningMinLength)
		b.WriteString("  text_hashes = true;\n  text_shingles = true;\n  html_shingles = false;\n")
		b.WriteString("  skip_images = true;\n  mime_types = [];\n  scan_archives = false;\n")
	}
	var b strings.Builder
	b.WriteString(ManagedHeader + "\nrule \"csm\" {\n")
	common(&b)
	b.WriteString("  read_only = true;\n")
	fmt.Fprintf(&b, "  fuzzy_map = { CSM_FUZZY_SPAM { flag = %d; max_score = %s; } }\n}\n", LearningFlag, learningMaxScore)
	b.WriteString("rule \"csm_learn\" {\n")
	common(&b)
	fmt.Fprintf(&b, "  write_encryption_key = %q;\n", k.Write.Public)
	b.WriteString("  mode = \"write_only\";\n  retransmits = 0;\n")
	fmt.Fprintf(&b, "  fuzzy_map = { CSM_FUZZY_LEARN { flag = %d; max_score = %s; } }\n}\n", LearningFlag, learningMaxScore)
	return b.String()
}

// renderLearningWorker writes the loopback fuzzy worker: encrypted traffic
// only, no address-based updates, and one keypair per operation set.
func renderLearningWorker(k LearningKeys) string {
	var b strings.Builder
	b.WriteString(ManagedHeader + "\ncount = 1;\n")
	fmt.Fprintf(&b, "bind_socket = %q;\n", learningServer)
	b.WriteString("backend = \"redis\";\n")
	fmt.Fprintf(&b, "prefix = %q;\n", k.Prefix)
	b.WriteString("expire = " + learningExpire + ";\nallow_update = [];\nencrypted_only = true;\n")
	for _, kp := range []struct {
		pair Keypair
		ops  string
	}{{k.Read, `"read"`}, {k.Write, `"read", "write", "delete"`}} {
		fmt.Fprintf(&b, "keypair {\n  privkey = %q;\n  pubkey = %q;\n  extensions { allowed_ops = [%s]; }\n}\n",
			kp.pair.Private.Reveal(), kp.pair.Public, kp.ops)
	}
	return b.String()
}
