package crawlid

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
)

// ErrBadKey reports an encoded key that does not decode under this version.
var ErrBadKey = errors.New("crawlid: malformed encoded key")

// Level selects the fields that participate in identity.
type Level uint8

const (
	L1 Level = 1 // site, first segment, exact parameter-name set
	L2 Level = 2 // site, first segment, non-empty query
	L3 Level = 3 // site, any dynamic GET/HEAD
)

// Key identifies one detector counter and one gate policy predicate. Site is
// the canonical site identity from the verified inventory, never a raw Host
// header. Components are borrowed and must remain immutable while used.
type Key struct {
	Level   Level
	Site    []byte
	Segment []byte
	Names   [][]byte
}

// KeysFor returns every level a request contributes to, broadest first.
func KeysFor(site []byte, c Class, t Target) []Key {
	if !c.Dynamic {
		return nil
	}
	keys := []Key{{Level: L3, Site: site}}
	if c.Expensive {
		keys = append(keys,
			Key{Level: L2, Site: site, Segment: t.Segment},
			Key{Level: L1, Site: site, Segment: t.Segment, Names: t.Names})
	}
	return keys
}

const keyMagic = "ck"

// Encode is the versioned, length-delimited binary form. Every component is
// uvarint-length-prefixed, so no byte value inside a component can forge a
// boundary.
func (k Key) Encode() []byte {
	b := append([]byte(keyMagic), byte(Version), byte(k.Level))
	b = appendField(b, k.Site)
	if k.Level == L1 || k.Level == L2 {
		b = appendField(b, k.Segment)
	}
	if k.Level == L1 {
		b = binary.AppendUvarint(b, uint64(len(k.Names)))
		for _, n := range k.Names {
			b = appendField(b, n)
		}
	}
	return b
}

// ID is a stable short display identifier, not an equality or authority check.
func (k Key) ID() string {
	h := sha256.Sum256(k.Encode())
	return base64.RawURLEncoding.EncodeToString(h[:16])
}

// DecodeKey parses Encode output and rejects anything else.
func DecodeKey(b []byte) (Key, error) {
	if len(b) < 4 || string(b[:2]) != keyMagic || b[2] != Version {
		return Key{}, ErrBadKey
	}
	k := Key{Level: Level(b[3])}
	if k.Level < L1 || k.Level > L3 {
		return Key{}, ErrBadKey
	}
	rest := b[4:]
	var ok bool
	if k.Site, rest, ok = readField(rest); !ok {
		return Key{}, ErrBadKey
	}
	if k.Level != L3 {
		if k.Segment, rest, ok = readField(rest); !ok {
			return Key{}, ErrBadKey
		}
	}
	if k.Level == L1 {
		n, w := binary.Uvarint(rest)
		// #nosec G115 -- positive Uvarint width is at most len(rest); the difference is nonnegative.
		if w <= 0 || n > uint64(len(rest)-w) {
			return Key{}, ErrBadKey
		}
		rest = rest[w:]
		k.Names = make([][]byte, 0, n)
		for i := uint64(0); i < n; i++ {
			var f []byte
			if f, rest, ok = readField(rest); !ok {
				return Key{}, ErrBadKey
			}
			if len(k.Names) > 0 && bytes.Compare(k.Names[len(k.Names)-1], f) >= 0 {
				return Key{}, ErrBadKey
			}
			k.Names = append(k.Names, f)
		}
	}
	if len(rest) != 0 || !bytes.Equal(k.Encode(), b) {
		return Key{}, ErrBadKey
	}
	return k, nil
}

func appendField(b, f []byte) []byte {
	b = binary.AppendUvarint(b, uint64(len(f)))
	return append(b, f...)
}

func readField(b []byte) (field, rest []byte, ok bool) {
	n, w := binary.Uvarint(b)
	// #nosec G115 -- positive Uvarint width is at most len(b); the difference is nonnegative.
	if w <= 0 || n > uint64(len(b)-w) {
		return nil, nil, false
	}
	// #nosec G115 -- n <= len(b)-w above, so both conversion and sum fit int.
	end := w + int(n)
	return b[w:end:end], b[end:], true
}
