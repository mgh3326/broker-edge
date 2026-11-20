package gatewayd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRunRefusesInvalidFetchConsumerConfigWithFixedText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consumers.json")
	if err := os.WriteFile(path, []byte(`{"consumers":[{"name":"a","providers":["toss"],"credential_env":"SECRET_CRED_ENV_NAME"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"REDIS_URL":                   "redis://127.0.0.1:1/0",
		"KIS_MOCK_APP_KEY":            "k",
		"KIS_MOCK_APP_SECRET":         "s",
		FetchConsumersFileEnv:         path,
		"GATEWAYD_LISTEN_ADDR":        "127.0.0.1:0",
		"SECRET_CRED_ENV_NAME_UNUSED": "x",
	}
	var stderr bytes.Buffer
	code := Run(context.Background(), nil, func(name string) string { return env[name] }, &stderr)
	if code != 1 || stderr.String() != "gatewayd: startup_failed\n" {
		t.Fatalf("Run = %d %q", code, stderr.String())
	}
}
