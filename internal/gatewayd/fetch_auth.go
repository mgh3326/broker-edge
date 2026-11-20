package gatewayd

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strings"
)

const (
	// FetchConsumersFileEnv names the env var holding the path of the consumer
	// config file. Unset means /fetch is off.
	FetchConsumersFileEnv = "GATEWAYD_FETCH_CONSUMERS_FILE"

	minConsumerCredentialLength = 16
	consumerFileLimit           = 64 * 1024
)

var (
	sha256HexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	envNamePattern   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// consumerFile is the strict on-disk shape:
//
//	{"consumers":[{"name":"fillwire","credential_sha256":"<64 hex>"|"credential_env":"NAME","providers":["toss"]}]}
type consumerFile struct {
	// A pointer so that a missing or null array is an error, not "no consumers";
	// `{"consumers":[]}` stays the explicit way to switch the route off.
	Consumers *[]consumerEntry `json:"consumers"`
}

// Credential fields are pointers so presence survives decoding: exactly one must
// be present, and a present field with an empty value is an error rather than
// indistinguishable from an absent one.
type consumerEntry struct {
	Name             string   `json:"name"`
	CredentialSHA256 *string  `json:"credential_sha256"`
	CredentialEnv    *string  `json:"credential_env"`
	Providers        []string `json:"providers"`
}

type fetchConsumer struct {
	name      string
	digest    [sha256.Size]byte
	providers map[TokenProvider]struct{}
}

// ConsumerAuth authenticates /fetch callers. Credentials are held only as
// SHA-256 digests, so neither the plaintext nor an env value outlives loading.
// A nil or empty ConsumerAuth authenticates nobody (default off).
type ConsumerAuth struct {
	consumers []fetchConsumer
}

// Enabled reports whether at least one consumer is configured.
func (auth *ConsumerAuth) Enabled() bool { return auth != nil && len(auth.consumers) > 0 }

// authenticate returns the consumer owning credential. Every configured
// consumer is compared in constant time with no early exit, so timing reveals
// neither which consumer matched nor how many exist beyond their count.
func (auth *ConsumerAuth) authenticate(credential string) (*fetchConsumer, bool) {
	if !auth.Enabled() || credential == "" {
		return nil, false
	}
	presented := sha256.Sum256([]byte(credential))
	var matched *fetchConsumer
	for index := range auth.consumers {
		consumer := &auth.consumers[index]
		if subtle.ConstantTimeCompare(presented[:], consumer.digest[:]) == 1 {
			matched = consumer
		}
	}
	return matched, matched != nil
}

func (consumer *fetchConsumer) allows(provider TokenProvider) bool {
	_, allowed := consumer.providers[provider]
	return allowed
}

// LoadFetchConsumers reads the consumer file at path; an empty path yields a
// disabled ConsumerAuth. lookup resolves credential_env names. Errors are fixed
// (errConfiguration) so no credential, path or env name can reach a log.
func LoadFetchConsumers(path string, lookup func(string) string) (*ConsumerAuth, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return &ConsumerAuth{}, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errConfiguration
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, consumerFileLimit+1))
	if err != nil || len(data) > consumerFileLimit {
		return nil, errConfiguration
	}
	return ParseFetchConsumers(data, lookup)
}

// ParseFetchConsumers validates the consumer config. An empty consumer list is
// valid and leaves /fetch off.
func ParseFetchConsumers(data []byte, lookup func(string) string) (*ConsumerAuth, error) {
	if lookup == nil {
		lookup = func(string) string { return "" }
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var parsed consumerFile
	if err := decoder.Decode(&parsed); err != nil || decoder.More() {
		return nil, errConfiguration
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errConfiguration
	}
	if parsed.Consumers == nil {
		return nil, errConfiguration
	}
	auth := &ConsumerAuth{}
	names := make(map[string]struct{}, len(*parsed.Consumers))
	digests := make(map[[sha256.Size]byte]struct{}, len(*parsed.Consumers))
	for _, entry := range *parsed.Consumers {
		consumer, err := entry.build(lookup)
		if err != nil {
			return nil, errConfiguration
		}
		if _, duplicate := names[consumer.name]; duplicate {
			return nil, errConfiguration
		}
		if _, duplicate := digests[consumer.digest]; duplicate {
			return nil, errConfiguration
		}
		names[consumer.name] = struct{}{}
		digests[consumer.digest] = struct{}{}
		auth.consumers = append(auth.consumers, consumer)
	}
	return auth, nil
}

func (entry consumerEntry) build(lookup func(string) string) (fetchConsumer, error) {
	name := strings.TrimSpace(entry.Name)
	if name == "" || len(entry.Providers) == 0 {
		return fetchConsumer{}, errConfiguration
	}
	if (entry.CredentialSHA256 == nil) == (entry.CredentialEnv == nil) {
		return fetchConsumer{}, errConfiguration
	}
	consumer := fetchConsumer{name: name, providers: make(map[TokenProvider]struct{}, len(entry.Providers))}
	if entry.CredentialSHA256 != nil {
		if !sha256HexPattern.MatchString(*entry.CredentialSHA256) {
			return fetchConsumer{}, errConfiguration
		}
		decoded, err := hex.DecodeString(*entry.CredentialSHA256)
		if err != nil || len(decoded) != sha256.Size {
			return fetchConsumer{}, errConfiguration
		}
		copy(consumer.digest[:], decoded)
	} else {
		if !envNamePattern.MatchString(*entry.CredentialEnv) {
			return fetchConsumer{}, errConfiguration
		}
		credential := strings.TrimSpace(lookup(*entry.CredentialEnv))
		if len(credential) < minConsumerCredentialLength || !safeHeaderText(credential) {
			return fetchConsumer{}, errConfiguration
		}
		consumer.digest = sha256.Sum256([]byte(credential))
	}
	for _, name := range entry.Providers {
		provider := TokenProvider(name)
		if !knownProvider(provider) {
			return fetchConsumer{}, errConfiguration
		}
		if _, duplicate := consumer.providers[provider]; duplicate {
			return fetchConsumer{}, errConfiguration
		}
		consumer.providers[provider] = struct{}{}
	}
	return consumer, nil
}
