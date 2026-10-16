package antispam

import (
	"fmt"
	"io/fs"
)

// Secret holds a Spamhaus DQS key with redacted formatting and encoding.
// Its zero value is empty; Reveal is for rendering.
type Secret struct {
	// fmt bypasses methods for invalid verbs and unexported fields. An
	// indirect value keeps those reflection fallbacks from printing the key.
	value *string
}

// NewSecret wraps a key without validating it. LoadDQSKey validates file facts.
func NewSecret(key string) Secret {
	if key == "" {
		return Secret{}
	}
	return Secret{value: &key}
}

const redacted = "[redacted]"

func (Secret) String() string               { return redacted }
func (Secret) GoString() string             { return redacted }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// Reveal returns the key for rendering into rspamd configuration.
func (s Secret) Reveal() string {
	if s.value == nil {
		return ""
	}
	return *s.value
}

// KeyFacts is the DQS key file as a collector found it. Key is set only for
// a regular file small enough to hold a key.
type KeyFacts struct {
	Path    string
	Missing bool
	UID     int
	Mode    fs.FileMode
	Key     Secret
	Err     error
}

// dqsKeyLen is the DQS key length Spamhaus documents.
const dqsKeyLen = 26

// LoadDQSKey checks the key file's owner and mode and the key's format, and
// returns the key. Errors name the path and the rule, never the content.
func LoadDQSKey(k KeyFacts) (Secret, error) {
	switch {
	case k.Missing:
		return Secret{}, fmt.Errorf("the Spamhaus DQS key file %s does not exist", k.Path)
	case k.Err != nil:
		return Secret{}, fmt.Errorf("cannot read the Spamhaus DQS key file %s; it must be a regular file", k.Path)
	case k.UID != 0:
		return Secret{}, fmt.Errorf("the Spamhaus DQS key file %s is owned by uid %d; want root", k.Path, k.UID)
	case k.Mode.Perm()&0o022 != 0:
		return Secret{}, fmt.Errorf("the Spamhaus DQS key file %s is writable by group or others", k.Path)
	case k.Mode.Perm()&0o004 != 0:
		return Secret{}, fmt.Errorf("the Spamhaus DQS key file %s is readable by others; make it mode 600", k.Path)
	case !validDQSKey(k.Key.Reveal()):
		return Secret{}, fmt.Errorf("the Spamhaus DQS key file %s does not hold a %d-character key of lowercase letters and digits", k.Path, dqsKeyLen)
	}
	return k.Key, nil
}

// validDQSKey accepts exactly dqsKeyLen lowercase ASCII letters and digits,
// so the key can sit inside a quoted UCL string and a DNS label.
func validDQSKey(key string) bool {
	if len(key) != dqsKeyLen {
		return false
	}
	for i := 0; i < len(key); i++ {
		if c := key[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
