package gatewayd

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/mgh3326/broker-edge/internal/kismockread"
)

type storedValue struct {
	value     string
	expiresAt time.Time
}

type setRecord struct {
	key   string
	value string
	ttl   time.Duration
}

type fakeRedisStore struct {
	mu sync.Mutex

	now    func() time.Time
	values map[string]storedValue
	locks  map[string]storedValue

	getErr   error
	setErr   error
	setNXErr error
	delErr   error
	deletes  []string
	markers  map[string]string
	// lostReply makes the next SetIfLockHeld commit and then report a transport
	// error, as when the connection drops before the reply arrives.
	lostReply bool

	sets             []setRecord
	setWhileLockHeld []bool
	setNXCalls       int
	setNXHit         chan struct{}
	setNXHook        func()
}

func newFakeRedisStore(now func() time.Time) *fakeRedisStore {
	return &fakeRedisStore{
		now:    now,
		values: make(map[string]storedValue),
		locks:  make(map[string]storedValue),
	}
}

func (store *fakeRedisStore) Get(_ context.Context, key string) (string, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.getErr != nil {
		return "", false, store.getErr
	}
	value, found := store.values[key]
	if !found || (!value.expiresAt.IsZero() && !store.now().Before(value.expiresAt)) {
		delete(store.values, key)
		return "", false, nil
	}
	return value.value, true, nil
}

func (store *fakeRedisStore) Set(_ context.Context, key, value string, ttl time.Duration) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.setErr != nil {
		return store.setErr
	}
	store.values[key] = storedValue{value: value, expiresAt: store.now().Add(ttl)}
	delete(store.markers, key)
	store.sets = append(store.sets, setRecord{key: key, value: value, ttl: ttl})
	store.setWhileLockHeld = append(store.setWhileLockHeld, store.hasActiveLockLocked())
	return nil
}

func (store *fakeRedisStore) hasActiveLockLocked() bool {
	for _, lock := range store.locks {
		if lock.expiresAt.IsZero() || store.now().Before(lock.expiresAt) {
			return true
		}
	}
	return false
}

func (store *fakeRedisStore) SetNX(_ context.Context, key, value string, ttl time.Duration) (bool, error) {
	if hook := store.setNXHook; hook != nil {
		hook()
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.setNXErr != nil {
		return false, store.setNXErr
	}
	store.setNXCalls++
	if store.setNXHit != nil && store.setNXCalls == 2 {
		close(store.setNXHit)
	}
	lock, found := store.locks[key]
	if found && (lock.expiresAt.IsZero() || store.now().Before(lock.expiresAt)) {
		return false, nil
	}
	store.locks[key] = storedValue{value: value, expiresAt: store.now().Add(ttl)}
	return true, nil
}

func (store *fakeRedisStore) CompareAndDelete(_ context.Context, key, value string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if lock, found := store.locks[key]; found && lock.value == value {
		delete(store.locks, key)
	}
	return nil
}

func (store *fakeRedisStore) save(key, value string, ttl time.Duration) {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.markers, key)
	store.values[key] = storedValue{value: value, expiresAt: store.now().Add(ttl)}
}

func (store *fakeRedisStore) savedRecords() []setRecord {
	store.mu.Lock()
	defer store.mu.Unlock()
	output := make([]setRecord, len(store.sets))
	copy(output, store.sets)
	return output
}

func (store *fakeRedisStore) savedWhileLocked() []bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	output := make([]bool, len(store.setWhileLockHeld))
	copy(output, store.setWhileLockHeld)
	return output
}

func (store *fakeRedisStore) lockAttempts() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.setNXCalls
}

type fakeOAuthIssuer struct {
	mu sync.Mutex

	token   OAuthToken
	err     error
	calls   int
	started chan struct{}
	release <-chan struct{}
}

func (issuer *fakeOAuthIssuer) Issue(ctx context.Context, _, _ string) (OAuthToken, error) {
	issuer.mu.Lock()
	issuer.calls++
	started := issuer.started
	release := issuer.release
	issuer.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-ctx.Done():
			return OAuthToken{}, ctx.Err()
		case <-release:
		}
	}
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	return issuer.token, issuer.err
}

func (issuer *fakeOAuthIssuer) callCount() int {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	return issuer.calls
}

func testGatewayConfig() Config {
	return Config{
		BaseURL:   kismockread.MockBaseURL,
		AppKey:    "app-key-for-test",
		AppSecret: "app-secret-for-test",
		RedisURL:  "redis://127.0.0.1:6379/0",
		Timeout:   time.Second,
	}
}

func testProviderConfig(provider TokenProvider) ProviderConfig {
	baseURL, found := providerBaseURL(provider)
	if !found {
		panic("unknown test provider")
	}
	config := ProviderConfig{
		Provider:  provider,
		BaseURL:   baseURL,
		AppKey:    "app-key-for-test",
		AppSecret: "app-secret-for-test",
	}
	if provider == ProviderToss {
		config.AppKey = "toss-client-id-for-test"
		config.AppSecret = "toss-client-secret-for-test"
	}
	return config
}

func newTestEnsureService(t *testing.T, store RedisStore, issuer OAuthIssuer, now time.Time) *EnsureService {
	t.Helper()
	service, err := NewEnsureService(store, issuer, testGatewayConfig())
	if err != nil {
		t.Fatal(err)
	}
	service.Now = func() time.Time { return now }
	return service
}

func newTestEnsureServiceForProvider(t *testing.T, store RedisStore, issuer OAuthIssuer, now time.Time, provider TokenProvider) *EnsureService {
	t.Helper()
	service, err := NewEnsureServiceForProvider(store, issuer, testProviderConfig(provider))
	if err != nil {
		t.Fatal(err)
	}
	service.Now = func() time.Time { return now }
	return service
}

func testGatewayNow() time.Time {
	return time.Unix(2_000_000_000, 0)
}

func (store *fakeRedisStore) TTL(_ context.Context, key string) (time.Duration, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.getErr != nil {
		return 0, store.getErr
	}
	v, ok := store.values[key]
	if !ok || v.expiresAt.IsZero() {
		return -1, nil
	}
	return v.expiresAt.Sub(store.now()), nil
}

func (store *fakeRedisStore) Held(_ context.Context, key string) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.getErr != nil {
		return false, store.getErr
	}
	if lock, ok := store.locks[key]; ok && (lock.expiresAt.IsZero() || store.now().Before(lock.expiresAt)) {
		return true, nil
	}
	v, ok := store.values[key]
	return ok && (v.expiresAt.IsZero() || store.now().Before(v.expiresAt)), nil
}

func (store *fakeRedisStore) SetIfLockHeld(_ context.Context, lockKey, lockValue, key, value string, ttl time.Duration, publication string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.setErr != nil {
		return store.setErr
	}
	lock, found := store.locks[lockKey]
	if !found || lock.value != lockValue || (!lock.expiresAt.IsZero() && !store.now().Before(lock.expiresAt)) {
		return errLockLost
	}
	expiresAt := store.now().Add(ttl)
	store.values[key] = storedValue{value: value, expiresAt: expiresAt}
	delete(store.markers, key)
	if publication != "" {
		if store.markers == nil {
			store.markers = map[string]string{}
		}
		store.markers[key] = publication + "@" + strconv.FormatInt(expiresAt.UnixMilli(), 10)
	}
	store.sets = append(store.sets, setRecord{key: key, value: value, ttl: ttl})
	store.setWhileLockHeld = append(store.setWhileLockHeld, true)
	if store.lostReply {
		store.lostReply = false
		return errRedisUnavailable
	}
	return nil
}

func (store *fakeRedisStore) GetWithTTL(_ context.Context, key string) (string, time.Duration, int64, string, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.getErr != nil {
		return "", 0, 0, "", false, store.getErr
	}
	value, found := store.values[key]
	if !found || (!value.expiresAt.IsZero() && !store.now().Before(value.expiresAt)) {
		return "", 0, 0, "", false, nil
	}
	if value.expiresAt.IsZero() {
		return value.value, -1, 0, "", true, nil
	}
	serverExpiry := value.expiresAt.UnixMilli()
	return value.value, value.expiresAt.Sub(store.now()), serverExpiry, boundPublication(store.markers[key], serverExpiry), true, nil
}

func (store *fakeRedisStore) WithdrawIfLockHeld(_ context.Context, lockKey, lockValue, key, expected string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.delErr != nil {
		return store.delErr
	}
	lock, found := store.locks[lockKey]
	if !found || lock.value != lockValue || (!lock.expiresAt.IsZero() && !store.now().Before(lock.expiresAt)) {
		return errLockLost
	}
	if current, present := store.values[key]; !present || current.value != expected {
		return errStateChanged
	}
	delete(store.values, key)
	delete(store.markers, key)
	store.deletes = append(store.deletes, key)
	return nil
}
