package gatewayd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	credentialFillwire = "fillwire-credential-0123456789abcdef"
	credentialOther    = "other-consumer-credential-0123456789"
	credentialEnvValue = "env-credential-0123456789abcdefgh"
)

func credentialDigest(credential string) string {
	sum := sha256.Sum256([]byte(credential))
	return hex.EncodeToString(sum[:])
}

// fetchServer is a handler over real Fetchers for the given providers.
type fetchServer struct {
	handler http.Handler
	logs    *bytes.Buffer
	metrics *Metrics
	h       map[TokenProvider]*fetchHarness
}

func newFetchServer(t *testing.T, consumersJSON string, providers ...TokenProvider) *fetchServer {
	t.Helper()
	auth, err := ParseFetchConsumers([]byte(consumersJSON), func(name string) string {
		if name == "FILLWIRE_FETCH_CREDENTIAL" {
			return credentialEnvValue
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	server := &fetchServer{logs: &bytes.Buffer{}, metrics: NewMetrics(), h: map[TokenProvider]*fetchHarness{}}
	fetchers := ProviderFetchers{}
	for _, provider := range providers {
		h := newFetchHarness(t, provider)
		server.h[provider] = h
		fetchers[provider] = h.fetcher
	}
	server.handler = newHandlerWithFetch(ProviderEnsurers{}, FetchOptions{Fetchers: fetchers, Auth: auth}, testLogger(server.logs), server.metrics)
	return server
}

func consumersJSON(t *testing.T) string {
	return fmt.Sprintf(`{"consumers":[
		{"name":"fillwire","credential_sha256":%q,"providers":["kis-mock","toss","kis-live-approval"]},
		{"name":"narrow","credential_sha256":%q,"providers":["kis-mock"]},
		{"name":"envconsumer","credential_env":"FILLWIRE_FETCH_CREDENTIAL","providers":["toss"]}]}`,
		credentialDigest(credentialFillwire), credentialDigest(credentialOther))
}

func (s *fetchServer) post(provider, credential, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/v1/tokens/"+provider+"/fetch", strings.NewReader(body))
	if credential != "" {
		request.Header.Set("Authorization", "Bearer "+credential)
	}
	response := httptest.NewRecorder()
	s.handler.ServeHTTP(response, request)
	return response
}

func TestFetchHTTPSuccessShape(t *testing.T) {
	server := newFetchServer(t, consumersJSON(t), ProviderKISMock, ProviderToss, ProviderKISLiveApproval)
	for _, provider := range []TokenProvider{ProviderKISMock, ProviderToss, ProviderKISLiveApproval} {
		h := server.h[provider]
		response := server.post(string(provider), credentialFillwire, `{}`)
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" ||
			response.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("%s: %d %v", provider, response.Code, response.Header())
		}
		decoder := json.NewDecoder(response.Body)
		decoder.DisallowUnknownFields()
		var body struct {
			Provider    string `json:"provider"`
			Token       string `json:"token"`
			ExpiresAt   string `json:"expires_at"`
			TokenSHA256 string `json:"token_sha256"`
			Source      string `json:"source"`
		}
		if err := decoder.Decode(&body); err != nil {
			t.Fatalf("%s: %v", provider, err)
		}
		wantExpiry := h.now.Add(time.Hour)
		if isApprovalProvider(provider) {
			wantExpiry = h.now.Add(approvalTTL)
		}
		if body.Provider != string(provider) || body.Token != tokenN(1) || body.TokenSHA256 != sha(tokenN(1)) ||
			body.Source != "issued" || body.ExpiresAt != wantExpiry.UTC().Format(time.RFC3339) || !strings.HasSuffix(body.ExpiresAt, "Z") {
			t.Fatalf("%s body = %+v", provider, body)
		}
		again := server.post(string(provider), credentialFillwire, "")
		if !strings.Contains(again.Body.String(), `"source":"memory"`) {
			t.Fatalf("%s repeat: %s", provider, again.Body.String())
		}
	}
}

func TestFetchHTTPFailedHashSemantics(t *testing.T) {
	server := newFetchServer(t, consumersJSON(t), ProviderToss)
	h := server.h[ProviderToss]
	server.post("toss", credentialFillwire, `{}`)
	stale := server.post("toss", credentialFillwire, `{"failed_token_sha256":"`+sha("older")+`"}`)
	if !strings.Contains(stale.Body.String(), tokenN(1)) || h.issuer.callCount() != 1 {
		t.Fatalf("stale report: %d calls %d", stale.Code, h.issuer.callCount())
	}
	forced := server.post("toss", credentialFillwire, `{"failed_token_sha256":"`+sha(tokenN(1))+`"}`)
	if !strings.Contains(forced.Body.String(), tokenN(2)) || !strings.Contains(forced.Body.String(), `"source":"issued"`) || h.issuer.callCount() != 2 {
		t.Fatalf("forced: %s", forced.Body.String())
	}
}

func TestFetchHTTPErrorContract(t *testing.T) {
	server := newFetchServer(t, consumersJSON(t), ProviderKISMock, ProviderToss)
	// Lock contention for kis-mock → 503.
	h := server.h[ProviderKISMock]
	h.store.SetNX(context.Background(), h.lockKey, "peer", time.Minute)

	failedHash := `{"failed_token_sha256":"` + sha("x") + `"}`
	cases := []struct {
		name, provider, credential, body string
		status                           int
		code                             string
	}{
		{"no credential", "toss", "", `{}`, 401, "unauthenticated"},
		{"wrong credential", "toss", "not-a-real-credential-0123456789", `{}`, 401, "unauthenticated"},
		{"credential before provider check", "no-such-provider", "not-a-real-credential-0123456789", `{}`, 401, "unauthenticated"},
		{"unknown provider", "no-such-provider", credentialFillwire, `{}`, 404, "unknown_provider"},
		{"known but not served", "kis-live", credentialFillwire, `{}`, 403, "provider_not_allowed"},
		{"not in allowlist", "toss", credentialOther, `{}`, 403, "provider_not_allowed"},
		{"allowed but not configured", "kis-live-approval", credentialFillwire, `{}`, 404, "unknown_provider"},
		{"unknown body field", "toss", credentialFillwire, `{"force":true}`, 400, "bad_request"},
		{"uppercase hash", "toss", credentialFillwire, `{"failed_token_sha256":"` + strings.ToUpper(sha("x")) + `"}`, 400, "bad_request"},
		{"short hash", "toss", credentialFillwire, `{"failed_token_sha256":"abc"}`, 400, "bad_request"},
		{"non-string hash", "toss", credentialFillwire, `{"failed_token_sha256":5}`, 400, "bad_request"},
		{"not json", "toss", credentialFillwire, `nope`, 400, "bad_request"},
		{"trailing data", "toss", credentialFillwire, `{} {}`, 400, "bad_request"},
		{"json null body", "toss", credentialFillwire, `null`, 400, "bad_request"},
		{"null hash", "toss", credentialFillwire, `{"failed_token_sha256":null}`, 400, "bad_request"},
		{"empty string hash", "toss", credentialFillwire, `{"failed_token_sha256":""}`, 400, "bad_request"},
		{"array body", "toss", credentialFillwire, `[]`, 400, "bad_request"},
		{"scalar body", "toss", credentialFillwire, `"x"`, 400, "bad_request"},
		{"oversize body", "toss", credentialFillwire, `{"failed_token_sha256":"` + strings.Repeat("a", 5000) + `"}`, 400, "bad_request"},
		{"lock contended", "kis-mock", credentialFillwire, failedHash, 503, "issue_unavailable"},
	}
	for _, c := range cases {
		response := server.post(c.provider, c.credential, c.body)
		if response.Code != c.status || response.Body.String() != `{"error":"`+c.code+`"}` ||
			response.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %q %v", c.name, response.Code, response.Body.String(), response.Header())
		}
	}
	if server.h[ProviderToss].issuer.callCount() != 0 || h.issuer.callCount() != 0 {
		t.Fatal("an error path issued a token")
	}
}

func TestFetchHTTPAuthSchemeAndEnvCredential(t *testing.T) {
	server := newFetchServer(t, consumersJSON(t), ProviderToss)
	for header, want := range map[string]int{
		"Bearer " + credentialEnvValue:                   200,
		"bearer " + credentialEnvValue:                   200,
		"Basic " + credentialEnvValue:                    401,
		credentialEnvValue:                               401,
		"Bearer":                                         401,
		"Bearer " + credentialEnvValue + "x":             401,
		"Bearer " + credentialDigest(credentialFillwire): 401, // the stored digest is not a credential
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/tokens/toss/fetch", strings.NewReader(`{}`))
		request.Header.Set("Authorization", header)
		response := httptest.NewRecorder()
		server.handler.ServeHTTP(response, request)
		if response.Code != want {
			t.Errorf("Authorization %q → %d, want %d", header, response.Code, want)
		}
	}
}

func TestFetchHTTPIsOffByDefault(t *testing.T) {
	now := testGatewayNow()
	store := newFakeRedisStore(func() time.Time { return now })
	service := newTestEnsureServiceForProvider(t, store, &seqIssuer{}, now, ProviderKISMock)
	var logs bytes.Buffer
	for name, handler := range map[string]http.Handler{
		"legacy constructor": NewHandler(ProviderEnsurers{ProviderKISMock: service}, testLogger(&logs)),
		"zero options":       newHandlerWithFetch(ProviderEnsurers{ProviderKISMock: service}, FetchOptions{Fetchers: ProviderFetchers{ProviderKISMock: service.NewFetcher()}}, testLogger(&logs), nil),
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/tokens/kis-mock/fetch", strings.NewReader(`{}`))
		request.Header.Set("Authorization", "Bearer "+credentialFillwire)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != 401 || response.Body.String() != `{"error":"unauthenticated"}` {
			t.Errorf("%s: %d %q", name, response.Code, response.Body.String())
		}
		// /ensure and /healthz still behave as before.
		ensure := httptest.NewRecorder()
		handler.ServeHTTP(ensure, httptest.NewRequest(http.MethodPost, "/v1/tokens/kis-mock/ensure", nil))
		if ensure.Code != 200 || ensure.Body.String() != `{"state":"issued"}` && ensure.Body.String() != `{"state":"fresh"}` {
			t.Errorf("%s ensure: %d %q", name, ensure.Code, ensure.Body.String())
		}
		health := httptest.NewRecorder()
		handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if health.Code != 200 || health.Body.String() != `{"status":"ok"}` {
			t.Errorf("%s healthz: %d", name, health.Code)
		}
	}
}

// The token and its prefix must not appear in any log line, error body or
// metric on any path, including an upstream error that quotes the token.
func TestFetchNeverLeaksTokenToLogsErrorsOrMetrics(t *testing.T) {
	const probe = "LEAKPROBE-9f3c1a77d2e84b5ca0de-token-value"
	var stdLog bytes.Buffer
	log.SetOutput(&stdLog)
	defer log.SetOutput(os.Stderr)

	providers := []TokenProvider{ProviderKISMock, ProviderToss, ProviderKISLiveApproval}
	server := newFetchServer(t, consumersJSON(t), providers...)
	for _, h := range server.h {
		h.issuer.tokenFn = func(int) string { return probe }
	}
	var responses []*httptest.ResponseRecorder
	post := func(provider, credential, body string) {
		responses = append(responses, server.post(provider, credential, body))
	}
	for _, provider := range []string{"kis-mock", "toss", "kis-live-approval"} {
		post(provider, credentialFillwire, `{}`)                                         // issued
		post(provider, credentialFillwire, `{}`)                                         // memory
		post(provider, credentialFillwire, `{"failed_token_sha256":"`+sha(probe)+`"}`)   // forced reissue
		post(provider, credentialFillwire, `{"failed_token_sha256":"`+sha("other")+`"}`) // stale
		post(provider, credentialFillwire, `{"nope":1}`)                                 // 400
		post(provider, "", `{}`)                                                         // 401
		post(provider, credentialOther, `{}`)                                            // 403 (toss, approval)
		post(provider+"-x", credentialFillwire, `{}`)                                    // 404
	}
	for _, provider := range []TokenProvider{ProviderKISMock, ProviderToss} {
		server.h[provider].issuer.mu.Lock()
		server.h[provider].issuer.err = fmt.Errorf("upstream rejected %s", probe)
		server.h[provider].issuer.mu.Unlock()
		post(string(provider), credentialFillwire, `{"failed_token_sha256":"`+sha(probe)+`"}`) // 503
	}
	metricsResponse := httptest.NewRecorder()
	server.handler.ServeHTTP(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metricsResponse.Body.String(), "gatewayd_fetch_results_total") {
		t.Fatal("metrics missing fetch counter")
	}

	for _, needle := range []string{probe, probe[:8], probe[:12]} {
		for name, text := range map[string]string{"logs": server.logs.String(), "stdlog": stdLog.String(), "metrics": metricsResponse.Body.String()} {
			if strings.Contains(text, needle) {
				t.Fatalf("%q leaked into %s", needle, name)
			}
		}
	}
	if server.logs.Len() == 0 {
		t.Fatal("expected fixed log lines")
	}
	errorBodies, successBodies := 0, 0
	for _, response := range responses {
		body := response.Body.String()
		if response.Code == http.StatusOK {
			successBodies++
			continue
		}
		errorBodies++
		if strings.Contains(body, probe[:8]) {
			t.Fatalf("error response leaked token: %s", body)
		}
	}
	if errorBodies < 13 || successBodies < 8 {
		t.Fatalf("exercised %d error and %d success responses", errorBodies, successBodies)
	}
	for _, secret := range []string{credentialFillwire, credentialOther, credentialEnvValue} {
		if strings.Contains(server.logs.String(), secret) || strings.Contains(server.logs.String(), credentialDigest(secret)) {
			t.Fatal("credential leaked to logs")
		}
	}
}

func TestFetchMetricsAreBoundedByProviderOutcomeAndSource(t *testing.T) {
	server := newFetchServer(t, consumersJSON(t), ProviderToss)
	server.post("toss", credentialFillwire, `{}`)
	server.post("toss", credentialFillwire, `{}`)
	server.post("toss", "", `{}`)
	server.post("attacker-controlled-"+strings.Repeat("z", 40), "", `{}`)
	response := httptest.NewRecorder()
	server.handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	text := response.Body.String()
	for _, want := range []string{
		`gatewayd_fetch_results_total{outcome="ok",provider="toss",source="issued"} 1`,
		`gatewayd_fetch_results_total{outcome="ok",provider="toss",source="memory"} 1`,
		`gatewayd_fetch_results_total{outcome="unauthenticated",provider="toss",source="none"} 1`,
		`gatewayd_fetch_results_total{outcome="unauthenticated",provider="unknown",source="none"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(text, "attacker-controlled") {
		t.Fatal("request-controlled text became a label")
	}
}
