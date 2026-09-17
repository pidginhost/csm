package checks

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEmailPasswordReferenceHashes(t *testing.T) {
	data, err := os.ReadFile("testdata/email_password_hashes.json")
	if err != nil {
		t.Fatal(err)
	}
	var reference struct {
		Fixtures []struct{ Scheme, Password, Stored, Source string }
	}
	if err := json.Unmarshal(data, &reference); err != nil {
		t.Fatal(err)
	}
	if len(reference.Fixtures) != 20 {
		t.Fatal("missing password reference fixtures")
	}
	for _, fixture := range reference.Fixtures {
		if fixture.Source == "" {
			t.Fatal("reference fixture is missing its source")
		}
		t.Run(fixture.Scheme, func(t *testing.T) {
			v := mustEmailPasswordVerifier(t, fixture.Stored)
			for _, candidate := range []string{fixture.Password, "incorrect-fixture", "", fixture.Password + "x"} {
				got, err := v.matches(context.Background(), candidate)
				if err != nil || got != (candidate == fixture.Password) {
					t.Fatalf("reference mismatch: matched=%t, err=%v", got, err)
				}
			}
			if strings.HasSuffix(fixture.Scheme, "-CRYPT") {
				_, raw, _ := strings.Cut(fixture.Stored, "}")
				v = mustEmailPasswordVerifier(t, raw)
				if got, err := v.matches(context.Background(), fixture.Password); err != nil || !got {
					t.Fatalf("unprefixed CRYPT reference mismatch: %v", err)
				}
			}
		})
	}
}

func TestEmailPasswordHashRejectsUnboundedOrUnsupportedInput(t *testing.T) {
	sha := "$6$salt$" + strings.Repeat("a", 86)
	argon := "$argon2id$v=19$m=65536,t=4,p=4$c2FsdHNhbHQ$MTIzNDU2Nzg5MDEyMzQ1Ng"
	for _, tc := range []struct {
		name, stored string
		want         error
	}{
		{"unknown", "{UNSUPPORTED}private-fixture", errEmailHashUnsupported},
		{"DES", "vpvKh.SaNbR6s", errEmailHashUnsupported},
		{"PBKDF2", "{PBKDF2}$1$salt$99999999$hash", errEmailHashUnsupported},
		{"huge input", strings.Repeat("x", maxEmailHashBytes+1), errEmailHashInvalid},
		{"NUL", "{PLAIN}fixture\x00secret", errEmailHashInvalid},
		{"missing brace", "{SHA512-CRYPT", errEmailHashInvalid},
		{"scheme mismatch", "{SHA256-CRYPT}" + sha, errEmailHashInvalid},
		{"invalid hash", strings.Replace(sha, "$salt$", "$salt$!", 1), errEmailHashInvalid},
		{"SHA low rounds", strings.Replace(sha, "$salt$", "$rounds=999$salt$", 1), errEmailHashInvalid},
		{"SHA high rounds", strings.Replace(sha, "$salt$", "$rounds=1000001$salt$", 1), errEmailHashCost},
		{"SHA overflow", strings.Replace(sha, "$salt$", "$rounds=4294967296$salt$", 1), errEmailHashCost},
		{"SHA duplicate rounds", strings.Replace(sha, "$salt$", "$rounds=1000,rounds=999999999$salt$", 1), errEmailHashInvalid},
		{"bcrypt expensive", "$2y$15$" + strings.Repeat("a", 53), errEmailHashCost},
		{"bcrypt low", "$2y$03$" + strings.Repeat("a", 53), errEmailHashInvalid},
		{"bcrypt legacy bug", "$2x$04$" + strings.Repeat("a", 53), errEmailHashUnsupported},
		{"argon memory", strings.Replace(argon, "m=65536", "m=65537", 1), errEmailHashCost},
		{"argon time", strings.Replace(argon, "t=4", "t=5", 1), errEmailHashCost},
		{"argon threads", strings.Replace(argon, "p=4", "p=5", 1), errEmailHashCost},
		{"argon zero", strings.Replace(argon, "t=4", "t=0", 1), errEmailHashInvalid},
		{"argon duplicate", strings.Replace(argon, "t=4", "m=1", 1), errEmailHashInvalid},
		{"argon missing", strings.Replace(argon, ",p=4", "", 1), errEmailHashInvalid},
		{"argon version", strings.Replace(argon, "v=19", "v=16", 1), errEmailHashInvalid},
		{"argon too little memory", strings.Replace(argon, "m=65536", "m=31", 1), errEmailHashInvalid},
		{"bad encoding", "{SHA.hex}fixture-secret", errEmailHashInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := parseEmailPasswordHash(tc.stored)
			if v != nil || !errors.Is(err, tc.want) {
				t.Fatalf("decoder = %v, %v; want %v", v, err, tc.want)
			}
		})
	}
	// Decode the upper limits without performing their expensive KDFs.
	for _, encoded := range []string{strings.Replace(sha, "$salt$", "$rounds=1000000$salt$", 1), argon, "$2y$14$" + strings.Repeat(".", 53)} {
		if _, err := parseEmailPasswordHash(encoded); err != nil {
			t.Fatalf("valid cost boundary rejected: %v", err)
		}
	}
}

func TestEmailPasswordCancellationRetainsWorkerSlots(t *testing.T) {
	started := make(chan struct{}, cap(emailHashes.slots)+1)
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	v := &emailPasswordVerifier{match: func(string) (bool, error) {
		started <- struct{}{}
		<-release
		return true, nil
	}}
	for range cap(emailHashes.slots) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { _, err := v.matches(ctx, "fixture"); done <- err }()
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("worker did not start")
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled worker returned %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("verification did not cancel promptly")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := v.matches(ctx, "fixture"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued verification returned %v", err)
	}
	if len(started) != 0 || len(emailHashes.slots) != cap(emailHashes.slots) {
		t.Fatal("cancellation released a still-running KDF slot")
	}
	once.Do(func() { close(release) })
	deadline := time.Now().Add(time.Second)
	for len(emailHashes.slots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(emailHashes.slots) != 0 {
		t.Fatal("completed workers leaked slots")
	}
	if got, err := mustEmailPasswordVerifier(t, "{PLAIN}fixture").matches(context.Background(), "fixture"); err != nil || !got {
		t.Fatalf("verification did not recover: %v", err)
	}
}

func TestEmailPasswordCandidateLimitsAndSafeErrors(t *testing.T) {
	calls := 0
	v := &emailPasswordVerifier{match: func(string) (bool, error) { calls++; return false, errors.New("fixture-secret") }}
	for _, candidate := range []string{strings.Repeat("x", maxEmailCandidateBytes+1), "fixture\x00secret"} {
		if _, err := v.matches(context.Background(), candidate); !errors.Is(err, errEmailCandidate) {
			t.Fatalf("invalid candidate returned %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := v.matches(ctx, "fixture"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled caller returned %v", err)
	}
	if calls != 0 {
		t.Fatal("rejected input reached the KDF")
	}
	if _, err := v.matches(context.Background(), strings.Repeat("x", maxEmailCandidateBytes)); !errors.Is(err, errEmailPasswordVerify) || strings.Contains(err.Error(), "fixture-secret") {
		t.Fatalf("verification error exposed input: %v", err)
	}
}

func TestEmailPasswordEncodingAndCryptVariants(t *testing.T) {
	const bcryptHash = "$2y$05$11ipvo5dR6CwkzwmhwM26OXgzXwhV2PyPuLV.Qi31ILcRcThQpEiW"
	for _, stored := range []string{
		"{pLaIn.b64}dGVzdA==", "{PLAIN.BASE64}dGVzdA==", "{SHA1}a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
		"{PLAIN-MD5}CY9rzUYh03PK3k6DJie09g==", "{SHA1.HeX}A94A8FE5CCB19BA61C4C0873D391E987982FBBD3",
		"{BLF-CRYPT}" + strings.Replace(bcryptHash, "$2y$", "$2a$", 1),
		"{BLF-CRYPT}" + strings.Replace(bcryptHash, "$2y$", "$2b$", 1),
	} {
		v := mustEmailPasswordVerifier(t, stored)
		for _, candidate := range []string{"test", "wrong"} {
			got, err := v.matches(context.Background(), candidate)
			if err != nil || got != (candidate == "test") {
				t.Fatalf("encoding/variant mismatch: matched=%t, err=%v", got, err)
			}
		}
	}
}
