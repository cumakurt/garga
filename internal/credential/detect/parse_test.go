package detect

import (
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/credential"
)

func TestParseUsersAndPasswords(t *testing.T) {
	t.Parallel()

	users, err := ParseUsers(strings.NewReader("elastic\n# comment\nadmin\n"))
	if err != nil {
		t.Fatalf("ParseUsers() error = %v", err)
	}
	if len(users) != 2 || users[0] != "elastic" || users[1] != "admin" {
		t.Fatalf("users = %#v", users)
	}

	passwords, err := ParsePasswords(strings.NewReader("password\n changeme \n"))
	if err != nil {
		t.Fatalf("ParsePasswords() error = %v", err)
	}
	if len(passwords) != 2 || string(passwords[0]) != "password" || string(passwords[1]) != "changeme" {
		t.Fatalf("passwords = %#v", passwords)
	}
}

func TestParsePairs(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	secrets, err := ParsePairs(strings.NewReader("basic alice " + canary + "\n# ignored\n"))
	if err != nil {
		t.Fatalf("ParsePairs() error = %v", err)
	}
	defer destroySecrets(secrets)
	if len(secrets) != 1 || secrets[0].Username() != "alice" {
		t.Fatalf("secrets = %#v", secrets)
	}
}

func TestParsePairsLeakFormats(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	input := strings.NewReader("alice:" + canary + "-colon\nbob," + canary + "-comma\ncarol " + canary + "-space\nbasic dave " + canary + "-basic\n")
	secrets, err := ParsePairs(input)
	if err != nil {
		t.Fatalf("ParsePairs() error = %v", err)
	}
	defer destroySecrets(secrets)
	want := []string{"alice", "bob", "carol", "dave"}
	if len(secrets) != len(want) {
		t.Fatalf("len(secrets) = %d, want %d", len(secrets), len(want))
	}
	for index, username := range want {
		if secrets[index].Username() != username {
			t.Fatalf("secrets[%d].Username() = %q, want %q", index, secrets[index].Username(), username)
		}
		if secrets[index].Kind() != credential.KindBasic {
			t.Fatalf("kind = %q", secrets[index].Kind())
		}
	}
}

func TestParsePairsRejectsAPIKey(t *testing.T) {
	t.Parallel()

	if _, err := ParsePairs(strings.NewReader("api_key example-id:example-key\n")); err == nil {
		t.Fatal("ParsePairs() accepted an API key line")
	}
}

func TestParseStructuredSprayInput(t *testing.T) {
	t.Parallel()

	input := strings.NewReader(`@users
elastic
admin
@passwords
password
changeme
`)
	users, passwords, err := ParseStructuredSprayInput(input)
	if err != nil {
		t.Fatalf("ParseStructuredSprayInput() error = %v", err)
	}
	if len(users) != 2 || len(passwords) != 2 {
		t.Fatalf("users=%#v passwords=%#v", users, passwords)
	}
}

func TestBuildSecretsSprayingOrder(t *testing.T) {
	t.Parallel()

	options := Defaults()
	options.Mode = ModeSpraying
	secrets, err := BuildSecrets(options, Input{
		Users:     []string{"alice", "bob"},
		Passwords: [][]byte{[]byte("p1"), []byte("p2")},
	})
	if err != nil {
		t.Fatalf("BuildSecrets() error = %v", err)
	}
	defer destroySecrets(secrets)

	want := []struct {
		username string
		password string
	}{
		{"alice", "p1"},
		{"bob", "p1"},
		{"alice", "p2"},
		{"bob", "p2"},
	}
	if len(secrets) != len(want) {
		t.Fatalf("len(secrets) = %d, want %d", len(secrets), len(want))
	}
	for index, expected := range want {
		if secrets[index].Username() != expected.username {
			t.Fatalf("secrets[%d].Username() = %q, want %q", index, secrets[index].Username(), expected.username)
		}
		header, headerErr := secrets[index].AuthorizationHeader()
		if headerErr != nil {
			t.Fatalf("AuthorizationHeader() error = %v", headerErr)
		}
		if !strings.Contains(header, "Basic ") {
			t.Fatalf("header = %q", header)
		}
	}
}

func TestBuildSecretsBruteForce(t *testing.T) {
	t.Parallel()

	options := Defaults()
	options.Mode = ModeBruteForce
	secrets, err := BuildSecrets(options, Input{
		Username:  "elastic",
		Passwords: [][]byte{[]byte("a"), []byte("b")},
	})
	if err != nil {
		t.Fatalf("BuildSecrets() error = %v", err)
	}
	defer destroySecrets(secrets)
	if len(secrets) != 2 {
		t.Fatalf("len(secrets) = %d, want 2", len(secrets))
	}
	for _, secret := range secrets {
		if secret.Username() != "elastic" {
			t.Fatalf("username = %q, want elastic", secret.Username())
		}
		if secret.Kind() != credential.KindBasic {
			t.Fatalf("kind = %q, want basic", secret.Kind())
		}
	}
}

func TestBuildSecretsDictionary(t *testing.T) {
	t.Parallel()

	options := Defaults()
	options.Mode = ModeDictionary
	secrets, err := BuildSecrets(options, Input{
		Username:  "elastic",
		Passwords: [][]byte{[]byte("a"), []byte("b")},
	})
	if err != nil {
		t.Fatalf("BuildSecrets() error = %v", err)
	}
	defer destroySecrets(secrets)
	if len(secrets) != 2 {
		t.Fatalf("len(secrets) = %d, want 2", len(secrets))
	}
}

func TestBuildSecretsBruteForceCharset(t *testing.T) {
	t.Parallel()

	options := Defaults()
	options.Mode = ModeBruteForce
	secrets, err := BuildSecrets(options, Input{
		Username:  "elastic",
		Charset:   "ab",
		MinLength: 1,
		MaxLength: 1,
	})
	if err != nil {
		t.Fatalf("BuildSecrets() error = %v", err)
	}
	defer destroySecrets(secrets)
	if len(secrets) != 2 {
		t.Fatalf("len(secrets) = %d, want 2", len(secrets))
	}
	for _, secret := range secrets {
		if secret.Username() != "elastic" {
			t.Fatalf("username = %q, want elastic", secret.Username())
		}
	}
}

func TestBuildSecretsRejectsCharsetOnDictionary(t *testing.T) {
	t.Parallel()

	options := Defaults()
	options.Mode = ModeDictionary
	if _, err := BuildSecrets(options, Input{Username: "elastic", Charset: "ab", MinLength: 1, MaxLength: 1}); err == nil {
		t.Fatal("dictionary accepted charset generation")
	}
}
