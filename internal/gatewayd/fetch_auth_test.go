package gatewayd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFetchConsumers(t *testing.T) {
	env := func(name string) string {
		if name == "GOOD_ENV" {
			return credentialEnvValue
		}
		if name == "SHORT_ENV" {
			return "short"
		}
		return ""
	}
	digest := credentialDigest(credentialFillwire)
	valid := `{"consumers":[{"name":"a","credential_sha256":"` + digest + `","providers":["toss","kis-mock"]}]}`
	auth, err := ParseFetchConsumers([]byte(valid), env)
	if err != nil || !auth.Enabled() {
		t.Fatalf("valid config: %v", err)
	}
	if consumer, ok := auth.authenticate(credentialFillwire); !ok || consumer.name != "a" || !consumer.allows(ProviderToss) || consumer.allows(ProviderKISLive) {
		t.Fatal("authenticate/allowlist")
	}
	if _, ok := auth.authenticate(""); ok {
		t.Fatal("empty credential authenticated")
	}
	if empty, err := ParseFetchConsumers([]byte(`{"consumers":[]}`), env); err != nil || empty.Enabled() {
		t.Fatal("empty list must be valid and off")
	}
	if off, err := LoadFetchConsumers("", env); err != nil || off.Enabled() {
		t.Fatal("no path must be off")
	}

	bad := map[string]string{
		"unknown top field":     `{"consumers":[],"x":1}`,
		"unknown entry field":   `{"consumers":[{"name":"a","credential_sha256":"` + digest + `","providers":["toss"],"x":1}]}`,
		"no name":               `{"consumers":[{"credential_sha256":"` + digest + `","providers":["toss"]}]}`,
		"no providers":          `{"consumers":[{"name":"a","credential_sha256":"` + digest + `","providers":[]}]}`,
		"unknown provider":      `{"consumers":[{"name":"a","credential_sha256":"` + digest + `","providers":["upbit"]}]}`,
		"duplicate provider":    `{"consumers":[{"name":"a","credential_sha256":"` + digest + `","providers":["toss","toss"]}]}`,
		"both credential kinds": `{"consumers":[{"name":"a","credential_sha256":"` + digest + `","credential_env":"GOOD_ENV","providers":["toss"]}]}`,
		"no credential":         `{"consumers":[{"name":"a","providers":["toss"]}]}`,
		"uppercase digest":      `{"consumers":[{"name":"a","credential_sha256":"` + strings.ToUpper(digest) + `","providers":["toss"]}]}`,
		"short digest":          `{"consumers":[{"name":"a","credential_sha256":"abcd","providers":["toss"]}]}`,
		"env unset":             `{"consumers":[{"name":"a","credential_env":"MISSING_ENV","providers":["toss"]}]}`,
		"env too short":         `{"consumers":[{"name":"a","credential_env":"SHORT_ENV","providers":["toss"]}]}`,
		"env bad name":          `{"consumers":[{"name":"a","credential_env":"bad name","providers":["toss"]}]}`,
		"duplicate name":        `{"consumers":[{"name":"a","credential_sha256":"` + digest + `","providers":["toss"]},{"name":"a","credential_sha256":"` + credentialDigest(credentialOther) + `","providers":["toss"]}]}`,
		"duplicate credential":  `{"consumers":[{"name":"a","credential_sha256":"` + digest + `","providers":["toss"]},{"name":"b","credential_sha256":"` + digest + `","providers":["toss"]}]}`,
		"trailing data":         valid + ` {}`,
		"not json":              `consumers`,
	}
	for name, config := range bad {
		if _, err := ParseFetchConsumers([]byte(config), env); err == nil {
			t.Errorf("%s accepted", name)
		} else if strings.Contains(err.Error(), credentialEnvValue) || strings.Contains(err.Error(), "GOOD_ENV") {
			t.Errorf("%s: error text leaks: %v", name, err)
		}
	}
}

func TestLoadFetchConsumersFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consumers.json")
	if err := os.WriteFile(path, []byte(consumersJSONForFile()), 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := LoadFetchConsumers(path, func(string) string { return credentialEnvValue })
	if err != nil || !auth.Enabled() {
		t.Fatalf("load: %v", err)
	}
	if _, err := LoadFetchConsumers(filepath.Join(t.TempDir(), "missing.json"), nil); err == nil {
		t.Fatal("missing file accepted")
	}
}

func consumersJSONForFile() string {
	return `{"consumers":[{"name":"env","credential_env":"FILLWIRE_FETCH_CREDENTIAL","providers":["toss"]}]}`
}
