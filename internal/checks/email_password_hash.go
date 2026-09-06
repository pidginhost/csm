package checks

import (
	"context"
	"crypto/md5"  // #nosec G501 -- Read-only verification of existing Dovecot MD5 hashes, never password creation.
	"crypto/sha1" // #nosec G505 -- Read-only verification of existing Dovecot SHA1 hashes, never password creation.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"strconv"
	"strings"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/algorithm/argon2"
	"github.com/go-crypt/crypt/algorithm/bcrypt"
	"github.com/go-crypt/crypt/algorithm/md5crypt"
	"github.com/go-crypt/crypt/algorithm/shacrypt"
)

const (
	maxEmailHashBytes      = 4096
	maxEmailCandidateBytes = 256
)

var (
	errEmailHashUnsupported = errors.New("unsupported password hash scheme")
	errEmailHashInvalid     = errors.New("malformed password hash")
	errEmailHashCost        = errors.New("password hash exceeds audit cost limits")
	errEmailPasswordVerify  = errors.New("password verification failed")
	errEmailCandidate       = errors.New("password candidate exceeds audit limits")
	emailHashSlots          = make(chan struct{}, 3)
)

type emailPasswordVerifier struct {
	match func(string) (bool, error)
}

func (v *emailPasswordVerifier) matches(ctx context.Context, candidate string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if len(candidate) > maxEmailCandidateBytes || strings.ContainsRune(candidate, 0) {
		return false, errEmailCandidate
	}
	select {
	case emailHashSlots <- struct{}{}:
	case <-ctx.Done():
		return false, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		<-emailHashSlots
		return false, err
	}
	type result struct {
		match bool
		err   error
	}
	done := make(chan result, 1)
	// KDFs cannot be interrupted. Keep their slot until they finish, even
	// when the caller cancels, so successive scans cannot pile up workers.
	go func() {
		defer func() { <-emailHashSlots }()
		match, err := v.match(candidate)
		if err != nil {
			// Decoder/KDF errors may embed secret input.
			err = errEmailPasswordVerify
		}
		done <- result{match, err}
	}()
	select {
	case got := <-done:
		if err := ctx.Err(); err != nil {
			return false, err
		}
		return got.match, got.err
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func (v *emailPasswordVerifier) firstMatch(ctx context.Context, candidates []string) (string, error) {
	for _, candidate := range candidates {
		matched, err := v.matches(ctx, candidate)
		if err != nil {
			return "", err
		}
		if matched {
			return candidate, nil
		}
	}
	return "", ctx.Err()
}

func parseEmailPasswordHash(stored string) (*emailPasswordVerifier, error) {
	if len(stored) == 0 || len(stored) > maxEmailHashBytes || strings.ContainsRune(stored, 0) {
		return nil, errEmailHashInvalid
	}
	scheme, encoded := "CRYPT", stored
	if strings.HasPrefix(stored, "{") {
		end := strings.IndexByte(stored, '}')
		if end < 2 {
			return nil, errEmailHashInvalid
		}
		scheme, encoded = strings.ToUpper(stored[1:end]), stored[end+1:]
	}
	base, encoding, _ := strings.Cut(scheme, ".")
	if encoding != "" && (base == "PLAIN" || strings.HasSuffix(base, "CRYPT") || strings.HasPrefix(base, "ARGON2")) {
		decoded, err := decodeEmailDigest(encoding, encoded)
		if err != nil {
			return nil, err
		}
		encoded, encoding = string(decoded), ""
		if strings.ContainsRune(encoded, 0) {
			return nil, errEmailHashInvalid
		}
	}
	switch base {
	case "PLAIN":
		return &emailPasswordVerifier{match: func(candidate string) (bool, error) {
			return subtle.ConstantTimeCompare([]byte(encoded), []byte(candidate)) == 1, nil
		}}, nil
	case "PLAIN-MD5", "LDAP-MD5", "SMD5", "SHA", "SHA1", "SSHA", "SHA256", "SSHA256", "SHA512", "SSHA512":
		return parseEmailDigest(base, encoding, encoded)
	case "CRYPT", "SHA512-CRYPT", "SHA256-CRYPT", "MD5-CRYPT", "BLF-CRYPT", "ARGON2I", "ARGON2ID":
		if encoding != "" {
			return nil, errEmailHashUnsupported
		}
	default:
		return nil, errEmailHashUnsupported
	}
	prefixes := map[string]string{
		"SHA512-CRYPT": "$6$", "SHA256-CRYPT": "$5$", "MD5-CRYPT": "$1$",
		"BLF-CRYPT": "$2", "ARGON2I": "$argon2i$", "ARGON2ID": "$argon2id$",
	}
	if prefix := prefixes[base]; prefix != "" && !strings.HasPrefix(encoded, prefix) {
		return nil, errEmailHashInvalid
	}
	decode, err := boundedEmailCryptDecoder(encoded)
	if err != nil {
		return nil, err
	}
	digest, err := decode(encoded)
	if err != nil {
		return nil, errEmailHashInvalid
	}
	return &emailPasswordVerifier{match: digest.MatchAdvanced}, nil
}

// Validate costs before a library sees the digest. Strict fields also prevent
// duplicate parameters or library defaults from changing the checked cost.
func boundedEmailCryptDecoder(encoded string) (func(string) (algorithm.Digest, error), error) {
	p := strings.Split(encoded, "$")
	if len(p) < 2 || p[0] != "" {
		return nil, errEmailHashUnsupported
	}
	switch p[1] {
	case "1", "5", "6":
		keyLen, saltMax := 22, 8
		if p[1] != "1" {
			saltMax, keyLen = 16, 43
			if p[1] == "6" {
				keyLen = 86
			}
			if len(p) == 5 {
				rounds, ok := strings.CutPrefix(p[2], "rounds=")
				if !ok {
					return nil, errEmailHashInvalid
				}
				if _, err := emailHashNumber(rounds, 1000, 1000000); err != nil {
					return nil, err
				}
				p = append(p[:2:2], p[3:]...)
			}
		}
		if len(p) != 4 || len(p[2]) > saltMax || !emailCryptChars(p[2]) || len(p[3]) != keyLen || !emailCryptChars(p[3]) {
			return nil, errEmailHashInvalid
		}
		if p[1] == "1" {
			return md5crypt.Decode, nil
		}
		return shacrypt.Decode, nil
	case "2a", "2b", "2y":
		if len(p) != 4 || len(p[2]) != 2 || len(p[3]) != 53 || !emailCryptChars(p[3]) {
			return nil, errEmailHashInvalid
		}
		if _, err := emailHashNumber(p[2], 4, 14); err != nil {
			return nil, err
		}
		return bcrypt.Decode, nil
	case "argon2i", "argon2id":
		if err := validateEmailArgon2(p); err != nil {
			return nil, err
		}
		return argon2.Decode, nil
	default:
		return nil, errEmailHashUnsupported
	}
}

func emailHashNumber(s string, min, max uint64) (uint64, error) {
	if s == "" || strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, errEmailHashInvalid
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n > max {
		return 0, errEmailHashCost
	}
	if n < min {
		return 0, errEmailHashInvalid
	}
	return n, nil
}

func emailCryptChars(s string) bool {
	return s != "" && strings.IndexFunc(s, func(r rune) bool {
		valid := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '/'
		return !valid
	}) < 0
}

func validateEmailArgon2(p []string) error {
	if len(p) != 6 || p[2] != "v=19" {
		return errEmailHashInvalid
	}
	params := strings.Split(p[3], ",")
	if len(params) != 3 {
		return errEmailHashInvalid
	}
	values := make(map[string]uint64, 3)
	limits := map[string]uint64{"m": 65536, "t": 4, "p": 4}
	for _, param := range params {
		key, value, ok := strings.Cut(param, "=")
		if !ok || limits[key] == 0 || values[key] != 0 {
			return errEmailHashInvalid
		}
		n, err := emailHashNumber(value, 1, limits[key])
		if err != nil {
			return err
		}
		values[key] = n
	}
	if values["m"] < 8*values["p"] {
		return errEmailHashInvalid
	}
	for i, field := range p[4:] {
		decoded, err := base64.RawStdEncoding.Strict().DecodeString(field)
		minLen := 8
		if i == 1 {
			minLen = 16
		}
		if err != nil || len(decoded) < minLen || len(decoded) > 64 {
			return errEmailHashInvalid
		}
	}
	return nil
}

func parseEmailDigest(scheme, encoding, encoded string) (*emailPasswordVerifier, error) {
	var newHash func() hash.Hash
	switch scheme {
	case "PLAIN-MD5", "LDAP-MD5", "SMD5":
		newHash = md5.New // #nosec G401 -- Verify legacy Dovecot hashes; never create stored credentials.
	case "SHA", "SHA1", "SSHA":
		newHash = sha1.New // #nosec G401 -- Verify legacy Dovecot hashes; never create stored credentials.
	case "SHA256", "SSHA256":
		newHash = sha256.New
	case "SHA512", "SSHA512":
		newHash = sha512.New
	}
	autoEncoding := encoding == ""
	if autoEncoding {
		encoding = "BASE64"
		if scheme == "PLAIN-MD5" {
			encoding = "HEX"
		}
	}
	decoded, err := decodeEmailDigest(encoding, encoded)
	size := newHash().Size()
	salted := strings.HasPrefix(scheme, "SSHA") || scheme == "SMD5"
	if autoEncoding && !salted && (err != nil || len(decoded) != size) {
		other := "HEX"
		if encoding == "HEX" {
			other = "BASE64"
		}
		decoded, err = decodeEmailDigest(other, encoded)
	}
	if err != nil || len(decoded) < size || !salted && len(decoded) != size || salted && (len(decoded) == size || len(decoded) > size+64) {
		return nil, errEmailHashInvalid
	}
	return &emailPasswordVerifier{match: func(candidate string) (bool, error) {
		h := newHash()
		_, _ = h.Write([]byte(candidate))
		_, _ = h.Write(decoded[size:])
		return subtle.ConstantTimeCompare(h.Sum(nil), decoded[:size]) == 1, nil
	}}, nil
}

func decodeEmailDigest(encoding, encoded string) ([]byte, error) {
	var decoded []byte
	var err error
	switch encoding {
	case "HEX":
		decoded, err = hex.DecodeString(encoded)
	case "B64", "BASE64":
		decoded, err = base64.StdEncoding.Strict().DecodeString(encoded)
	default:
		return nil, errEmailHashUnsupported
	}
	if err != nil {
		return nil, errEmailHashInvalid
	}
	return decoded, nil
}
