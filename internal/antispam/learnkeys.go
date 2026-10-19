package antispam

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"path"
	"strconv"
	"strings"
)

// Learning key file names under the learning directory's keys/ subdirectory.
const (
	KeyFuzzy    = "fuzzy.key"
	KeyShingles = "shingles.key"
	KeyRead     = "read.keypair"
	KeyWrite    = "write.keypair"
	KeyPrefix   = "prefix"
)

// LearningKeyNames lists the key files in creation order: the prefix comes
// last, so a crash during first generation leaves an incomplete set.
var LearningKeyNames = []string{KeyFuzzy, KeyShingles, KeyRead, KeyWrite, KeyPrefix}

// Hash-affecting values both CSM fuzzy rules pin (spec 6.2). Changing any of
// them changes every digest, so they are part of the hash generation.
const (
	LearningMinLength    = 32
	learningTextHashOpts = "text_hashes=true;text_shingles=true;html_shingles=false;skip_images=true;mime_types=[];scan_archives=false"
)

// Keypair is an rspamd curve25519 keypair from `rspamadm keypair -j`, both
// halves in rspamd's base32 encoding.
type Keypair struct {
	Public  string
	Private Secret
}

// LearningKeys are the secrets of one learning installation: the two hash
// keys and the Redis prefix define the hash generation; the keypairs only
// authorize reads and writes to the fuzzy storage.
type LearningKeys struct {
	Fuzzy, Shingles Secret
	Read, Write     Keypair
	Prefix          string
}

// HashGeneration identifies the two hash keys without revealing them: the
// learner's ledger is bound to it, so a new key set never reuses old state.
func (k LearningKeys) HashGeneration() string {
	sum := sha256.Sum256([]byte("csm-learning-hash-keys\x00" + k.Fuzzy.Reveal() + "\x00" + k.Shingles.Reveal()))
	return hex.EncodeToString(sum[:])
}

// rspamdKeyLen is the base32 length of a 32-byte curve25519 key.
const rspamdKeyLen = 52

// rspamdBase32 is rspamd's base32 alphabet.
const rspamdBase32 = "ybndrfg8ejkmcpqxot1uwisza345h769"

// Validate checks both halves are rspamd base32 keys. Errors never carry
// the private key.
func (k Keypair) Validate() error {
	if !validRspamdKey(k.Public) {
		return errors.New("public key is not a 52-character rspamd base32 key")
	}
	if !validRspamdKey(k.Private.Reveal()) {
		return errors.New("private key is not a 52-character rspamd base32 key")
	}
	return nil
}

func validRspamdKey(s string) bool {
	if len(s) != rspamdKeyLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(rspamdBase32, s[i]) < 0 {
			return false
		}
	}
	return true
}

// LearningKeyPaths maps each key file name to its path under dir/keys.
func LearningKeyPaths(dir string) map[string]string {
	out := make(map[string]string, len(LearningKeyNames))
	for _, name := range LearningKeyNames {
		out[name] = path.Join(dir, "keys", name)
	}
	return out
}

// HashGeneration identifies the digests a key set produces: hex SHA-256 over
// the hash keys, the prefix and the pinned hash options, each length
// prefixed. The transport keypairs are left out; they change no digest.
func HashGeneration(k LearningKeys) string {
	h := sha256.New()
	for _, field := range []string{
		"csm-learning-generation-v1",
		k.Fuzzy.Reveal(), k.Shingles.Reveal(), k.Prefix,
		strconv.Itoa(LearningMinLength), learningTextHashOpts,
	} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(field)))
		h.Write(n[:])
		h.Write([]byte(field))
	}
	return hex.EncodeToString(h.Sum(nil))
}
