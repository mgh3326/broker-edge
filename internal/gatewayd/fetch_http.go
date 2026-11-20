package gatewayd

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const fetchBodyLimit = 4096

// FetchOptions wires the /fetch route. The zero value answers 401 to everyone:
// with no consumer configured the route is off.
type FetchOptions struct {
	Fetchers ProviderFetchers
	Auth     *ConsumerAuth
}

type fetchRequest struct {
	FailedTokenSHA256 *string `json:"failed_token_sha256"`
}

type fetchResponse struct {
	Provider    string      `json:"provider"`
	Token       string      `json:"token"`
	ExpiresAt   string      `json:"expires_at"`
	TokenSHA256 string      `json:"token_sha256"`
	Source      FetchSource `json:"source"`
}

// fetchHandler serves POST /v1/tokens/{provider}/fetch. Every log line is fixed
// text and every error body is a bare code: the token value, the failed hash,
// the credential and the request path never reach a log, label or error.
func fetchHandler(options FetchOptions, logger EventLogger, metrics *Metrics) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		provider := TokenProvider(request.PathValue("provider"))
		fail := func(status int, code string, message string) {
			logEvent(logger, message)
			metrics.recordFetch(provider, code, "")
			writeFetchError(writer, status, code)
		}
		consumer, authenticated := options.Auth.authenticate(bearerCredential(request))
		if !authenticated {
			fail(http.StatusUnauthorized, "unauthenticated", "gatewayd: token fetch unauthenticated")
			return
		}
		if !knownProvider(provider) {
			fail(http.StatusNotFound, "unknown_provider", "gatewayd: token fetch unknown provider")
			return
		}
		if !consumer.allows(provider) {
			fail(http.StatusForbidden, "provider_not_allowed", "gatewayd: token fetch provider not allowed")
			return
		}
		fetcher, configured := options.Fetchers[provider]
		if !configured || fetcher == nil {
			fail(http.StatusNotFound, "unknown_provider", "gatewayd: token fetch provider not configured")
			return
		}
		failedSHA256, valid := decodeFetchRequest(writer, request)
		if !valid {
			fail(http.StatusBadRequest, "bad_request", "gatewayd: token fetch bad request")
			return
		}
		token, err := fetcher.Fetch(request.Context(), failedSHA256)
		if err != nil || token.Token == "" || token.SHA256 == "" {
			fail(http.StatusServiceUnavailable, "issue_unavailable", "gatewayd: token fetch unavailable")
			return
		}
		body, err := json.Marshal(fetchResponse{
			Provider:    string(provider),
			Token:       token.Token,
			ExpiresAt:   token.ExpiresAt.UTC().Format(time.RFC3339),
			TokenSHA256: token.SHA256,
			Source:      token.Source,
		})
		if err != nil {
			fail(http.StatusServiceUnavailable, "issue_unavailable", "gatewayd: token fetch unavailable")
			return
		}
		logEvent(logger, "gatewayd: token fetch served")
		metrics.recordFetch(provider, fetchOutcomeOK, token.Source)
		writer.Header().Set("content-type", "application/json")
		writer.Header().Set("cache-control", "no-store")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(body)
	}
}

func bearerCredential(request *http.Request) string {
	header := request.Header.Get("Authorization")
	scheme, credential, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(credential)
}

// decodeFetchRequest accepts {} or {"failed_token_sha256": "<64 lowercase hex>"}
// (an empty body counts as {}). Unknown fields, trailing data, a non-string or
// malformed hash, and oversize bodies are all bad requests.
func decodeFetchRequest(writer http.ResponseWriter, request *http.Request) (string, bool) {
	data, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, fetchBodyLimit))
	if err != nil {
		return "", false
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return "", true
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var parsed fetchRequest
	if err := decoder.Decode(&parsed); err != nil {
		return "", false
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return "", false
	}
	if parsed.FailedTokenSHA256 == nil {
		return "", true
	}
	if !sha256HexPattern.MatchString(*parsed.FailedTokenSHA256) {
		return "", false
	}
	return *parsed.FailedTokenSHA256, true
}

func writeFetchError(writer http.ResponseWriter, status int, code string) {
	writer.Header().Set("content-type", "application/json")
	writer.Header().Set("cache-control", "no-store")
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, `{"error":"`+code+`"}`)
}
