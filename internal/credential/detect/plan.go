package detect

import (
	"fmt"

	"github.com/cumakurt/garga/internal/credential"
)

// BuildSecrets materializes the credential attempt sequence for the selected mode.
func BuildSecrets(options Options, input Input) ([]*credential.Secret, error) {
	secrets, err := buildSecrets(options, input)
	zeroPasswordList(input.Passwords)
	return secrets, err
}

func buildSecrets(options Options, input Input) ([]*credential.Secret, error) {
	switch options.Mode {
	case ModeStuffing:
		if input.Charset != "" {
			return nil, fmt.Errorf("build credential detection plan: stuffing does not generate charset candidates")
		}
		if len(input.Pairs) == 0 {
			return nil, fmt.Errorf("build credential detection plan: stuffing requires credential pairs")
		}
		return input.Pairs, nil
	case ModeSpraying:
		if input.Charset != "" {
			return nil, fmt.Errorf("build credential detection plan: spraying does not generate charset candidates")
		}
		if len(input.Users) == 0 || len(input.Passwords) == 0 {
			return nil, fmt.Errorf("build credential detection plan: spraying requires usernames and passwords")
		}
		return buildSpraying(input.Users, input.Passwords)
	case ModeBruteForce:
		passwords := input.Passwords
		if input.Charset != "" {
			if len(passwords) > 0 {
				return nil, fmt.Errorf("build credential detection plan: brute-force charset cannot be combined with a password list")
			}
			generated, err := GeneratePasswords(input.Charset, input.MinLength, input.MaxLength)
			if err != nil {
				return nil, fmt.Errorf("build credential detection plan: %w", err)
			}
			passwords = generated
			defer zeroPasswordList(generated)
		}
		if input.Username == "" || len(passwords) == 0 {
			return nil, fmt.Errorf("build credential detection plan: brute-force requires one username and a password list or charset")
		}
		return buildBruteForce(input.Username, passwords)
	case ModeDictionary:
		if input.Charset != "" {
			return nil, fmt.Errorf("build credential detection plan: dictionary mode does not generate charset candidates")
		}
		if input.Username == "" || len(input.Passwords) == 0 {
			return nil, fmt.Errorf("build credential detection plan: dictionary requires one username and a wordlist")
		}
		return buildBruteForce(input.Username, input.Passwords)
	default:
		return nil, fmt.Errorf("build credential detection plan: unsupported mode %q", options.Mode)
	}
}

// Input holds parsed operator material for one detection run.
type Input struct {
	Username  string
	Users     []string
	Passwords [][]byte
	Pairs     []*credential.Secret
	Charset   string
	MinLength int
	MaxLength int
}

func buildSpraying(users []string, passwords [][]byte) ([]*credential.Secret, error) {
	total := len(users) * len(passwords)
	if total > maxPairs {
		return nil, fmt.Errorf("build credential detection plan: spraying would exceed %d attempts", maxPairs)
	}
	secrets := make([]*credential.Secret, 0, total)
	for _, password := range passwords {
		for _, username := range users {
			secret, err := credential.NewBasic(username, append([]byte(nil), password...))
			if err != nil {
				destroySecrets(secrets)
				return nil, fmt.Errorf("build credential detection plan: invalid basic credential")
			}
			secrets = append(secrets, secret)
		}
	}
	return secrets, nil
}

func buildBruteForce(username string, passwords [][]byte) ([]*credential.Secret, error) {
	if len(passwords) > maxPasswords {
		return nil, fmt.Errorf("build credential detection plan: at most %d passwords are allowed", maxPasswords)
	}
	secrets := make([]*credential.Secret, 0, len(passwords))
	for _, password := range passwords {
		secret, err := credential.NewBasic(username, append([]byte(nil), password...))
		if err != nil {
			destroySecrets(secrets)
			return nil, fmt.Errorf("build credential detection plan: invalid basic credential")
		}
		secrets = append(secrets, secret)
	}
	return secrets, nil
}

func zeroPasswordList(passwords [][]byte) {
	for index := range passwords {
		zero(passwords[index])
	}
}
