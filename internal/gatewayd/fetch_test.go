package gatewayd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingStore counts every Redis read so a memory hit can be proven to make
// none.
type countingStore struct {
	*fakeRedisStore
	reads atomic.Int64
	// separateReads counts GET and PTTL, which the approval fetch path must not
	// use (it reads value and TTL atomically).
	separateReads atomic.Int64
	// getHook runs once, after the next GET has read its value and before it
	// returns: it models another actor publishing during a read.
	hookMu         sync.Mutex
	getHook        func()
	getWithTTLHook func()
	afterSetHook   func()
	// failGetOn makes the Nth GET (1-based, counting GET and PTTL) fail;
	// getDelay slows every GET.
	failGetOn atomic.Int64
	getDelay  time.Duration
}

func (store *countingStore) Get(ctx context.Context, key string) (string, bool, error) {
	store.reads.Add(1)
	n := store.separateReads.Add(1)
	if store.getDelay > 0 {
		time.Sleep(store.getDelay)
	}
	if store.failGetOn.Load() == n {
		return "", false, errors.New("redis read failed")
	}
	value, present, err := store.fakeRedisStore.Get(ctx, key)
	store.hookMu.Lock()
	hook := store.getHook
	store.getHook = nil
	store.hookMu.Unlock()
	if hook != nil {
		hook()
	}
	return value, present, err
}

func (store *countingStore) TTL(ctx context.Context, key string) (time.Duration, error) {
	store.reads.Add(1)
	store.separateReads.Add(1)
	return store.fakeRedisStore.TTL(ctx, key)
}

func (store *countingStore) GetWithTTL(ctx context.Context, key string) (string, time.Duration, int64, string, bool, error) {
	store.reads.Add(1)
	store.hookMu.Lock()
	hook := store.getWithTTLHook
	store.getWithTTLHook = nil
	store.hookMu.Unlock()
	if hook != nil {
		hook()
	}
	return store.fakeRedisStore.GetWithTTL(ctx, key)
}

// SetIfLockHeld runs afterSetHook (once) after a successful publish, before the
// caller learns of it: it models an external writer publishing right after.
func (store *countingStore) SetIfLockHeld(ctx context.Context, lockKey, lockValue, key, value string, ttl time.Duration, publication string) error {
	err := store.fakeRedisStore.SetIfLockHeld(ctx, lockKey, lockValue, key, value, ttl, publication)
	store.hookMu.Lock()
	hook := store.afterSetHook
	if err == nil {
		store.afterSetHook = nil
	} else {
		hook = nil
	}
	store.hookMu.Unlock()
	if hook != nil {
		hook()
	}
	return err
}

func (store *countingStore) onNextGet(hook func()) {
	store.hookMu.Lock()
	store.getHook = hook
	store.hookMu.Unlock()
}

// seqIssuer hands out a distinct token per call, so a reissue is observable.
type seqIssuer struct {
	mu      sync.Mutex
	calls   int
	started chan struct{}
	release chan struct{}
	err     error
	tokenFn func(n int) string
	// onIssue runs inside Issue (e.g. to let a fake clock advance).
	onIssue  func()
	gateOnce sync.Once
	// deadline is the deadline of the context the last Issue call received.
	deadline time.Time
}

func (issuer *seqIssuer) Issue(ctx context.Context, _, _ string) (OAuthToken, error) {
	issuer.mu.Lock()
	issuer.calls++
	n := issuer.calls
	started, release, err, tokenFn, onIssue := issuer.started, issuer.release, issuer.err, issuer.tokenFn, issuer.onIssue
	issuer.deadline, _ = ctx.Deadline()
	issuer.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return OAuthToken{}, ctx.Err()
		}
	}
	if onIssue != nil {
		onIssue()
	}
	if err != nil {
		return OAuthToken{}, err
	}
	token := tokenN(n)
	if tokenFn != nil {
		token = tokenFn(n)
	}
	return OAuthToken{AccessToken: token, ExpiresIn: 3600}, nil
}

// releaseAll opens the gate for every blocked and future Issue call, once.
func (issuer *seqIssuer) releaseAll() {
	issuer.gateOnce.Do(func() {
		issuer.mu.Lock()
		release := issuer.release
		issuer.mu.Unlock()
		if release != nil {
			close(release)
		}
	})
}

// waitStarted waits (bounded) for an Issue call to begin.
func waitStarted(t *testing.T, started <-chan struct{}) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the broker was never called")
	}
}

func (issuer *seqIssuer) callCount() int {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	return issuer.calls
}

func tokenN(n int) string { return fmt.Sprintf("SECRETTOKEN-%d-0123456789abcdef", n) }

func sha(token string) string { return newFetchedToken(token, time.Time{}).SHA256 }

// fetchHarness is one provider's service + Fetcher over a counting Redis.
type fetchHarness struct {
	t       *testing.T
	now     time.Time
	store   *countingStore
	issuer  *seqIssuer
	fetcher *Fetcher
	// cacheKey/lockKey are the provider's existing Redis keys.
	cacheKey, lockKey string
	provider          TokenProvider
	ensurer           Ensurer
	// writeRedis puts another issuer's token into Redis the way its Python
	// writer would.
	writeRedis func(token string, expiresIn int64)
}

func newFetchHarness(t *testing.T, provider TokenProvider) *fetchHarness {
	t.Helper()
	h := &fetchHarness{t: t, now: testGatewayNow(), issuer: &seqIssuer{}, provider: provider}
	clock := func() time.Time { return h.now }
	h.store = &countingStore{fakeRedisStore: newFakeRedisStore(clock)}
	h.attach(h.store)
	t.Cleanup(func() { h.issuer.releaseAll() })
	return h
}

// attach (re)builds the service and Fetcher over store: a process start.
func (h *fetchHarness) attach(store *countingStore) {
	h.t.Helper()
	clock := func() time.Time { return h.now }
	if isApprovalProvider(h.provider) {
		service, err := newApprovalService(store, testProviderConfig(h.provider), time.Second)
		if err != nil {
			h.t.Fatal(err)
		}
		service.issuer, service.now = h.issuer, clock
		h.cacheKey, h.lockKey = service.cacheKey, service.lockKey
		h.fetcher, h.ensurer = service.newFetcher(), service
		h.writeRedis = func(token string, _ int64) { store.save(service.cacheKey, token, approvalTTL) }
	} else {
		service := newTestEnsureServiceForProvider(h.t, store, h.issuer, h.now, h.provider)
		service.Now = clock
		h.cacheKey, h.lockKey = service.CacheKey, service.LockKey
		h.fetcher, h.ensurer = service.NewFetcher(), service
		h.writeRedis = func(token string, expiresIn int64) {
			payload, err := service.payload(token, expiresIn, h.now)
			if err != nil {
				h.t.Fatal(err)
			}
			store.save(service.CacheKey, payload, providerCacheTTL(h.provider, expiresIn))
		}
	}
	h.fetcher.InitialLockWait, h.fetcher.LockPollEvery, h.fetcher.LockWaitTimeout = 0, time.Millisecond, 40*time.Millisecond
}

func (h *fetchHarness) fetch(failed string) FetchedToken {
	h.t.Helper()
	token, err := h.fetcher.Fetch(context.Background(), failed)
	if err != nil {
		h.t.Fatalf("fetch: %v", err)
	}
	return token
}

var fetchProviders = []TokenProvider{ProviderKISMock, ProviderKISLive, ProviderToss, ProviderKISLiveApproval, ProviderKISMockApproval}

func TestFetchIssuesThenServesFromMemoryWithZeroRedisReads(t *testing.T) {
	for _, provider := range fetchProviders {
		t.Run(string(provider), func(t *testing.T) {
			h := newFetchHarness(t, provider)
			first := h.fetch("")
			if first.Source != FetchSourceIssued || first.Token != tokenN(1) || first.SHA256 != sha(tokenN(1)) {
				t.Fatalf("first fetch = %v source %s", first.SHA256, first.Source)
			}
			wantExpiry := h.now.Add(time.Hour)
			if isApprovalProvider(provider) {
				wantExpiry = h.now.Add(approvalTTL)
			}
			if !first.ExpiresAt.Equal(wantExpiry) {
				t.Fatalf("expires_at = %v, want %v", first.ExpiresAt, wantExpiry)
			}
			reads := h.store.reads.Load()
			attempts := h.store.lockAttempts()
			for range 5 {
				again := h.fetch("")
				if again.Source != FetchSourceMemory || again.Token != tokenN(1) {
					t.Fatalf("repeat fetch source = %s", again.Source)
				}
			}
			if got := h.store.reads.Load(); got != reads {
				t.Fatalf("memory hits made %d Redis reads", got-reads)
			}
			if h.store.lockAttempts() != attempts || h.issuer.callCount() != 1 {
				t.Fatalf("memory hits touched the lock or issuer")
			}
		})
	}
}

func TestFetchIssueWritesRedisExactlyLikeEnsure(t *testing.T) {
	for _, provider := range fetchProviders {
		t.Run(string(provider), func(t *testing.T) {
			viaFetch := newFetchHarness(t, provider)
			viaFetch.fetch("")

			viaEnsure := newFetchHarness(t, provider)
			var ensurer Ensurer
			if isApprovalProvider(provider) {
				service, _ := newApprovalService(viaEnsure.store, testProviderConfig(provider), time.Second)
				service.issuer = viaEnsure.issuer
				ensurer = service
			} else {
				ensurer = newTestEnsureServiceForProvider(t, viaEnsure.store, viaEnsure.issuer, viaEnsure.now, provider)
			}
			if _, err := ensurer.Ensure(context.Background()); err != nil {
				t.Fatal(err)
			}
			got, want := viaFetch.store.savedRecords(), viaEnsure.store.savedRecords()
			if len(got) != 1 || len(want) != 1 || got[0] != want[0] {
				t.Fatalf("Redis writes differ:\nfetch  %#v\nensure %#v", got, want)
			}
			if held := viaFetch.store.savedWhileLocked(); len(held) != 1 || !held[0] {
				t.Fatal("fetch published to Redis outside the issuance lock")
			}
		})
	}
}

func TestFetchRestartLoadsFromRedisWithoutIssuing(t *testing.T) {
	for _, provider := range fetchProviders {
		t.Run(string(provider), func(t *testing.T) {
			h := newFetchHarness(t, provider)
			h.fetch("")
			if h.issuer.callCount() != 1 {
				t.Fatal("setup issue")
			}
			// A new process: same Redis, empty memory.
			restarted := newFetchHarness(t, provider)
			restarted.store.fakeRedisStore = h.store.fakeRedisStore
			restarted.issuer = &seqIssuer{}
			restarted.attach(restarted.store)

			lazy := restarted.fetch("")
			if lazy.Source != FetchSourceRedis || lazy.Token != tokenN(1) {
				t.Fatalf("restart fetch source = %s", lazy.Source)
			}
			if restarted.issuer.callCount() != 0 {
				t.Fatal("restart reissued")
			}
			if again := restarted.fetch(""); again.Source != FetchSourceMemory {
				t.Fatalf("second fetch source = %s", again.Source)
			}

			// Warm at start: the very first fetch is already a memory hit.
			warmed := newFetchHarness(t, provider)
			warmed.store.fakeRedisStore = h.store.fakeRedisStore
			warmed.issuer = &seqIssuer{}
			warmed.attach(warmed.store)
			warmed.fetcher.Warm(context.Background())
			reads := warmed.store.reads.Load()
			if got := warmed.fetch(""); got.Source != FetchSourceMemory || got.Token != tokenN(1) {
				t.Fatalf("warmed fetch source = %s", got.Source)
			}
			if warmed.store.reads.Load() != reads || warmed.issuer.callCount() != 0 {
				t.Fatal("warmed fetch read Redis or issued")
			}
		})
	}
}

func TestFetchNearExpiryTokenIsReplaced(t *testing.T) {
	h := newFetchHarness(t, ProviderKISMock)
	h.fetch("")
	h.now = h.now.Add(time.Hour - fetchMinRemaining) // exactly 60 s left: not "more than"
	got := h.fetch("")
	if got.Source != FetchSourceIssued || got.Token != tokenN(2) {
		t.Fatalf("near-expiry fetch = source %s", got.Source)
	}
}

func TestFetchFailedHashEqualForcesOneIssueUnderLock(t *testing.T) {
	for _, provider := range fetchProviders {
		t.Run(string(provider), func(t *testing.T) {
			h := newFetchHarness(t, provider)
			first := h.fetch("")
			got := h.fetch(first.SHA256)
			if got.Source != FetchSourceIssued || got.Token != tokenN(2) || h.issuer.callCount() != 2 {
				t.Fatalf("forced fetch = source %s calls %d", got.Source, h.issuer.callCount())
			}
			held := h.store.savedWhileLocked()
			if len(held) != 2 || !held[1] {
				t.Fatalf("forced issue published outside the lock: %v", held)
			}
			if next := h.fetch(""); next.Source != FetchSourceMemory || next.Token != tokenN(2) {
				t.Fatalf("after force, memory serves %s", next.Source)
			}
		})
	}
}

func TestFetchFailedHashDifferentReturnsCurrentWithoutIssuing(t *testing.T) {
	for _, provider := range fetchProviders {
		t.Run(string(provider), func(t *testing.T) {
			h := newFetchHarness(t, provider)
			first := h.fetch("")
			stale := sha("a-token-this-caller-held-before-a-reissue")
			got := h.fetch(stale)
			// The report is resolved against Redis, which still holds the current token.
			if got.Source != FetchSourceRedis || got.Token != first.Token || h.issuer.callCount() != 1 {
				t.Fatalf("stale report = source %s calls %d", got.Source, h.issuer.callCount())
			}
		})
	}
}

func TestFetchFailedReportAdoptsDifferentTokenFromRedis(t *testing.T) {
	for _, provider := range fetchProviders {
		t.Run(string(provider), func(t *testing.T) {
			h := newFetchHarness(t, provider)
			first := h.fetch("")
			// Another issuer (AT Python, self mode) replaces the Redis key.
			h.writeRedis("EXTERNAL-ISSUER-TOKEN-0123456789", 3600)
			got := h.fetch(first.SHA256)
			if got.Source != FetchSourceRedis || got.Token != "EXTERNAL-ISSUER-TOKEN-0123456789" {
				t.Fatalf("adopt = source %s", got.Source)
			}
			if h.issuer.callCount() != 1 {
				t.Fatal("adoption issued")
			}
			reads := h.store.reads.Load()
			if next := h.fetch(""); next.Source != FetchSourceMemory || next.Token != got.Token || h.store.reads.Load() != reads {
				t.Fatal("adopted token not served from memory")
			}
		})
	}
}

func TestFetchFailedReportWithSameRedisTokenStillIssues(t *testing.T) {
	h := newFetchHarness(t, ProviderToss)
	first := h.fetch("")
	if got := h.fetch(first.SHA256); got.Source != FetchSourceIssued {
		t.Fatalf("source = %s", got.Source)
	}
	if h.issuer.callCount() != 2 {
		t.Fatalf("issuer calls = %d", h.issuer.callCount())
	}
}

func TestFetchConcurrentFetchesIssueOnce(t *testing.T) {
	h := newFetchHarness(t, ProviderToss)
	h.issuer.started = make(chan struct{}, 1)
	h.issuer.release = make(chan struct{})
	results := make(chan FetchedToken, 16)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := h.fetcher.Fetch(context.Background(), "")
			if err != nil {
				t.Errorf("fetch: %v", err)
				return
			}
			results <- token
		}()
	}
	waitStarted(t, h.issuer.started)
	h.issuer.releaseAll()
	wg.Wait()
	close(results)
	issued := 0
	for token := range results {
		if token.Token != tokenN(1) {
			t.Fatalf("token = %s", token.Source)
		}
		if token.Source == FetchSourceIssued {
			issued++
		}
	}
	if issued != 1 || h.issuer.callCount() != 1 {
		t.Fatalf("issued %d, issuer calls %d", issued, h.issuer.callCount())
	}
}

func TestFetchConcurrentFailedReportsReissueOnce(t *testing.T) {
	h := newFetchHarness(t, ProviderKISLive)
	first := h.fetch("")
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := h.fetcher.Fetch(context.Background(), first.SHA256)
			if err != nil || token.Token != tokenN(2) {
				t.Errorf("fetch = %v err %v", token.Source, err)
			}
		}()
	}
	wg.Wait()
	if h.issuer.callCount() != 2 {
		t.Fatalf("issuer calls = %d, want 2", h.issuer.callCount())
	}
}

func TestFetchAcrossProcessesIssuesOnceUnderRedisLock(t *testing.T) {
	a := newFetchHarness(t, ProviderKISMock)
	b := newFetchHarness(t, ProviderKISMock)
	b.store.fakeRedisStore = a.store.fakeRedisStore
	b.issuer = a.issuer
	b.attach(b.store)
	b.fetcher.LockWaitTimeout = 5 * time.Second
	a.issuer.started = make(chan struct{}, 1)
	a.issuer.release = make(chan struct{})

	firstDone := make(chan FetchedToken, 1)
	go func() {
		token, _ := a.fetcher.Fetch(context.Background(), "")
		firstDone <- token
	}()
	waitStarted(t, a.issuer.started)
	secondDone := make(chan FetchedToken, 1)
	go func() {
		token, _ := b.fetcher.Fetch(context.Background(), "")
		secondDone <- token
	}()
	// The second process must be waiting on the lock, not issuing.
	deadline := time.After(2 * time.Second)
	for b.store.lockAttempts() < 2 {
		select {
		case <-deadline:
			t.Fatal("second process never reached the lock")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	a.issuer.releaseAll()
	first, second := <-firstDone, <-secondDone
	if first.Source != FetchSourceIssued || second.Source != FetchSourceRedis || first.Token != second.Token {
		t.Fatalf("sources %s/%s", first.Source, second.Source)
	}
	if a.issuer.callCount() != 1 {
		t.Fatalf("issuer calls = %d", a.issuer.callCount())
	}
}

func TestFetchContendedLockWithoutPublishIsUnavailableAndNeverIssues(t *testing.T) {
	h := newFetchHarness(t, ProviderKISMock)
	if locked, _ := h.store.SetNX(context.Background(), h.lockKey, "someone-else", time.Minute); !locked {
		t.Fatal("setup lock")
	}
	if _, err := h.fetcher.Fetch(context.Background(), ""); err == nil {
		t.Fatal("expected unavailable")
	}
	if h.issuer.callCount() != 0 || len(h.store.savedRecords()) != 0 {
		t.Fatal("issued or wrote without owning the lock")
	}
}

func TestFetchIssueFailureIsUnavailable(t *testing.T) {
	t.Run("kis-mock keeps its still-valid token", func(t *testing.T) {
		h := newFetchHarness(t, ProviderKISMock)
		first := h.fetch("")
		h.issuer.err = fmt.Errorf("broker said %s", first.Token)
		if _, err := h.fetcher.Fetch(context.Background(), first.SHA256); err != errFetchUnavailable {
			t.Fatalf("err = %v", err)
		}
		h.issuer.err = nil
		if got := h.fetch(""); got.Source != FetchSourceMemory || got.Token != first.Token {
			t.Fatalf("memory after failed reissue = %s", got.Source)
		}
	})
	t.Run("toss was withdrawn before the call, so the next request reissues", func(t *testing.T) {
		h := newFetchHarness(t, ProviderToss)
		first := h.fetch("")
		h.issuer.err = fmt.Errorf("broker said %s", first.Token)
		if _, err := h.fetcher.Fetch(context.Background(), first.SHA256); err != errFetchUnavailable {
			t.Fatalf("err = %v", err)
		}
		if _, present, _ := h.store.Get(context.Background(), h.cacheKey); present {
			t.Fatal("the shared predecessor was left readable across the broker call")
		}
		h.issuer.err = nil
		if got := h.fetch(""); got.Source != FetchSourceIssued || got.Token == first.Token {
			t.Fatalf("after a failed rotation: %s", got.Source)
		}
	})
}

func TestFetchRedisReadErrorIsUnavailable(t *testing.T) {
	h := newFetchHarness(t, ProviderKISMock)
	h.store.getErr = fmt.Errorf("redis down")
	if _, err := h.fetcher.Fetch(context.Background(), ""); err != errFetchUnavailable {
		t.Fatalf("err = %v", err)
	}
	if h.issuer.callCount() != 0 {
		t.Fatal("issued with Redis unreadable")
	}
}

func TestEnsureIssuePopulatesFetchMemory(t *testing.T) {
	now := testGatewayNow()
	store := &countingStore{fakeRedisStore: newFakeRedisStore(func() time.Time { return now })}
	issuer := &seqIssuer{}
	service := newTestEnsureServiceForProvider(t, store, issuer, now, ProviderToss)
	fetcher := service.NewFetcher()
	if state, err := service.Ensure(context.Background()); err != nil || state != EnsureStateIssued {
		t.Fatalf("ensure = %s %v", state, err)
	}
	reads := store.reads.Load()
	got, err := fetcher.Fetch(context.Background(), "")
	if err != nil || got.Source != FetchSourceMemory || got.Token != tokenN(1) || store.reads.Load() != reads {
		t.Fatalf("fetch after ensure = %s %v", got.Source, err)
	}
}

func TestParseCachedTokenPayloadShapes(t *testing.T) {
	good := `{"access_token":"abc","expires_at":2000003600.5,"created_at":2000000000.0}`
	if token, expiresAt, ok := parseCachedTokenPayload(ProviderKISLive, good); !ok || token != "abc" || expiresAt.Unix() != 2000003600 {
		t.Fatalf("kis payload = %q %v %v", token, expiresAt, ok)
	}
	for name, raw := range map[string]string{
		"toss with created_at": good,
		"unknown field":        `{"access_token":"abc","expires_at":2000003600,"x":1}`,
		"duplicate":            `{"access_token":"a","access_token":"b","expires_at":2000003600}`,
		"empty token":          `{"access_token":"","expires_at":2000003600}`,
		"not json":             `abc`,
		"missing expiry":       `{"access_token":"abc"}`,
	} {
		provider := ProviderKISMock
		if name == "toss with created_at" {
			provider = ProviderToss
		}
		if _, _, ok := parseCachedTokenPayload(provider, raw); ok {
			t.Errorf("%s accepted", name)
		}
	}
	if _, _, ok := parseCachedTokenPayload(ProviderToss, `{"access_token":"abc","expires_at":2000003600}`); !ok {
		t.Error("toss two-field payload rejected")
	}
}

func TestFetchedTokenFormattingIsRedacted(t *testing.T) {
	token := newFetchedToken("SECRETTOKEN-redaction", time.Unix(1, 0))
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(format, token); containsAny(out, "SECRETTOKEN") {
			t.Fatalf("%s leaked: %s", format, out)
		}
	}
}

func containsAny(text string, needles ...string) bool {
	for _, needle := range needles {
		if needle != "" && strings.Contains(text, needle) {
			return true
		}
	}
	return false
}
