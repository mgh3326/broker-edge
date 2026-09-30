package kismockedge

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	executioncontracts "github.com/mgh3326/broker-edge/execution_contracts"
)

func TestMaskedRejectionRemovesEverySecretShape(t *testing.T) {
	config := testBrokerConfig()
	token := "cached-token-for-test"
	masker := newSecretMasker(config, token)
	body := map[string]json.RawMessage{
		"rt_cd":  json.RawMessage(`"1"`),
		"msg_cd": json.RawMessage(`"APBK0957"`),
		"msg1": json.RawMessage(`"order refused for 12345678-01 (12345678) token cached-token-for-test key app-key-for-test secret app-secret-for-test"`),
	}
	rejection := maskedRejection(http.StatusOK, body, masker)
	if rejection == nil {
		t.Fatal("rejection missing")
	}
	if rejection.RtCd != "1" || rejection.MsgCd != "APBK0957" {
		t.Fatalf("fields = %#v", rejection)
	}
	for _, secret := range []string{"12345678", "12345678-01", token, config.AppKey, config.AppSecret} {
		if strings.Contains(rejection.Msg1, secret) {
			t.Fatalf("secret %q survived in msg1 %q", secret, rejection.Msg1)
		}
	}
	if !strings.Contains(rejection.Msg1, redactedValue) {
		t.Fatalf("no redaction marker in %q", rejection.Msg1)
	}
}

func TestMaskedRejectionStatusOnlyWhenBodyUnparseable(t *testing.T) {
	rejection := maskedRejection(http.StatusBadGateway, nil, newSecretMasker(testBrokerConfig(), "tok"))
	if rejection == nil || rejection.HTTPStatus != http.StatusBadGateway {
		t.Fatalf("rejection = %#v", rejection)
	}
	if rejection.RtCd != "" || rejection.MsgCd != "" || rejection.Msg1 != "" {
		t.Fatalf("fields present on unparseable body: %#v", rejection)
	}
	if maskedRejection(0, nil, newSecretMasker(testBrokerConfig(), "tok")) != nil {
		t.Fatal("no HTTP response must yield no rejection")
	}
}

func TestMaskedRejectionBoundsFields(t *testing.T) {
	masker := newSecretMasker(testBrokerConfig(), "tok")
	long := strings.Repeat("가", 1000)
	body := map[string]json.RawMessage{"msg1": json.RawMessage(`"` + long + `"`)}
	rejection := maskedRejection(http.StatusOK, body, masker)
	if got := len([]rune(rejection.Msg1)); got != maxRejectionMsgLength {
		t.Fatalf("msg1 runes = %d, want %d", got, maxRejectionMsgLength)
	}
}

func TestBrokerSendAttachesMaskedRejection(t *testing.T) {
	transport := &countingTransport{respond: func(*http.Request) (*http.Response, error) {
		return testHTTPResponse(http.StatusOK, `{"rt_cd":"1","msg_cd":"APBK0957","msg1":"balance check failed for 12345678-01 bearer cached-token-for-test"}`), nil
	}}
	broker := testKISMockBroker(transport)
	prepared, code := broker.Prepare(context.Background(), testCommand("rej-1"))
	if prepared == nil || code != "" {
		t.Fatalf("prepare code=%q", code)
	}
	result := prepared.Send(context.Background())
	if result.Accepted || result.ErrorCode != ErrorBrokerUnknown {
		t.Fatalf("result = %#v", result)
	}
	if result.Rejection == nil {
		t.Fatal("rejection missing")
	}
	if result.Rejection.HTTPStatus != http.StatusOK || result.Rejection.RtCd != "1" || result.Rejection.MsgCd != "APBK0957" {
		t.Fatalf("rejection = %#v", result.Rejection)
	}
	for _, secret := range []string{"12345678", "cached-token-for-test", "app-key-for-test", "app-secret-for-test"} {
		if strings.Contains(result.Rejection.Msg1, secret) {
			t.Fatalf("secret %q survived in %#v", secret, result.Rejection)
		}
	}
}

func TestBrokerSendAttachesRejectionOn5xxAndNonJSON(t *testing.T) {
	transport := &countingTransport{respond: func(*http.Request) (*http.Response, error) {
		return testHTTPResponse(http.StatusBadGateway, `<html>gateway 12345678-01</html>`), nil
	}}
	broker := testKISMockBroker(transport)
	prepared, _ := broker.Prepare(context.Background(), testCommand("rej-5xx"))
	result := prepared.Send(context.Background())
	if result.ErrorCode != ErrorBroker5xx || result.Rejection == nil || result.Rejection.HTTPStatus != http.StatusBadGateway {
		t.Fatalf("result = %#v", result)
	}
	if strings.Contains(result.Rejection.Msg1, "12345678") {
		t.Fatalf("account survived: %#v", result.Rejection)
	}
}

func TestRejectionReachesReceiptButNotStore(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "edge.sqlite"))
	transport := &countingTransport{respond: func(*http.Request) (*http.Response, error) {
		return testHTTPResponse(http.StatusOK, `{"rt_cd":"1","msg_cd":"APBK0957","msg1":"denied 12345678-01"}`), nil
	}}
	service := newTestService(store, testKISMockBroker(transport), true)
	receipt, err := service.Process(context.Background(), testCommand("rej-store"))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if receipt.Disposition != executioncontracts.DispositionUnknown || receipt.ErrorCode != ErrorBrokerUnknown {
		t.Fatalf("receipt = %#v", receipt)
	}
	if receipt.Rejection == nil || receipt.Rejection.RtCd != "1" || strings.Contains(receipt.Rejection.Msg1, "12345678") {
		t.Fatalf("rejection = %#v", receipt.Rejection)
	}
	stored, found, err := store.Find(context.Background(), "rej-store")
	if err != nil || !found {
		t.Fatalf("find: %v %v", found, err)
	}
	if stored.Rejection != nil {
		t.Fatalf("rejection must never persist: %#v", stored.Rejection)
	}
}
