package gatewayd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"sync"
	"time"
)

// fetchMinRemaining is the contract's "more than 60 s left" rule for serving a
// token from memory or from Redis. It is deliberately the same for every
// provider (Toss's longer /ensure buffer does not apply to /fetch).
const fetchMinRemaining = 60 * time.Second

var errFetchUnavailable = errors.New("token fetch unavailable")

// FetchSource says where a served token came from.
type FetchSource string

const (
	FetchSourceMemory FetchSource = "memory"
	FetchSourceRedis  FetchSource = "redis"
	FetchSourceIssued FetchSource = "issued"
)

// FetchedToken is a token value with its expiry. It is the only type that
// carries token material between the Fetcher and the HTTP boundary, so its
// formatting is redacted: a stray %v, %+v or %#v cannot leak the value.
type FetchedToken struct {
	Token     string
	ExpiresAt time.Time
	SHA256    string
	Source    FetchSource
}

func newFetchedToken(token string, expiresAt time.Time) FetchedToken {
	sum := sha256.Sum256([]byte(token))
	return FetchedToken{Token: token, ExpiresAt: expiresAt, SHA256: hex.EncodeToString(sum[:])}
}

func (t FetchedToken) String() string   { return "gatewayd.FetchedToken{redacted}" }
func (t FetchedToken) GoString() string { return t.String() }

func (t FetchedToken) usable(now time.Time) bool {
	return t.Token != "" && t.ExpiresAt.Sub(now) > fetchMinRemaining
}

func (t FetchedToken) from(source FetchSource) FetchedToken {
	t.Source = source
	return t
}

// TokenFetcher is the only capability the /fetch HTTP boundary needs.
// failedSHA256 is "" or the lowercase hex digest of a token the caller was
// refused with.
type TokenFetcher interface {
	Fetch(ctx context.Context, failedSHA256 string) (FetchedToken, error)
}

// ProviderFetchers contains only explicitly configured providers.
type ProviderFetchers map[TokenProvider]TokenFetcher

// tokenMemory is one provider's in-process copy of its current token.
type tokenMemory struct {
	mu    sync.Mutex
	token FetchedToken
}

func newTokenMemory() *tokenMemory { return &tokenMemory{} }

func (m *tokenMemory) get() FetchedToken {
	if m == nil {
		return FetchedToken{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.token
}

func (m *tokenMemory) put(token FetchedToken) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.token = token
	m.mu.Unlock()
}

// fetchBackend is the provider-specific half of a Fetcher: how the existing
// Redis key is read and how the existing issuance path writes it.
type fetchBackend interface {
	// readRedis returns the token currently stored in the provider's existing
	// Redis key. present is false for a missing or malformed value; freshness is
	// the caller's decision.
	readRedis(ctx context.Context, now time.Time) (token FetchedToken, present bool, err error)
	// issueAndStore performs one OAuth issue and writes Redis exactly as
	// /ensure does. The caller already owns the Redis lock.
	issueAndStore(ctx context.Context) (FetchedToken, error)
	redisLockKey() string
	redisLockTTL() time.Duration
}

// Fetcher serves one provider's token from memory, Redis or a fresh issue.
// Issuance is serialised in-process by issueMu and across processes by the same
// Redis lock /ensure uses.
type Fetcher struct {
	Store   RedisStore
	backend fetchBackend
	memory  *tokenMemory
	Now     func() time.Time

	InitialLockWait time.Duration
	LockPollEvery   time.Duration
	LockWaitTimeout time.Duration

	issueMu sync.Mutex
}

// NewFetcher builds the /fetch capability for this provider. It shares the
// service's memory so an /ensure-driven issue is visible to /fetch.
func (service *EnsureService) NewFetcher() *Fetcher {
	return &Fetcher{
		Store:           service.Store,
		backend:         service,
		memory:          service.memory,
		Now:             service.now,
		InitialLockWait: service.initialLockWait(),
		LockPollEvery:   service.lockPollEvery(),
		LockWaitTimeout: service.lockWaitTimeout(),
	}
}

func (s *approvalService) newFetcher() *Fetcher {
	return &Fetcher{
		Store:           s.store,
		backend:         s,
		memory:          s.memory,
		Now:             func() time.Time { return s.now() },
		InitialLockWait: lockInitialWait,
		LockPollEvery:   lockPollInterval,
		LockWaitTimeout: lockWaitTimeout,
	}
}

func (f *Fetcher) now() time.Time {
	if f.Now == nil {
		return time.Now()
	}
	return f.Now()
}

// Warm loads the provider's token from Redis into memory without ever issuing.
// It is best effort: a Redis error or an unusable value leaves memory empty and
// the first Fetch does the same read.
func (f *Fetcher) Warm(ctx context.Context) {
	if f == nil || f.backend == nil {
		return
	}
	now := f.now()
	if token, present, err := f.backend.readRedis(ctx, now); err == nil && present && token.usable(now) {
		f.memory.put(token)
	}
}

// Fetch implements the /fetch contract:
//   - no failed hash: serve a token with more than 60 s left, else issue;
//   - failed hash equal to the current token: reissue (unless Redis already
//     holds a different usable token, which is adopted);
//   - failed hash different: the caller is stale, serve the current token.
func (f *Fetcher) Fetch(ctx context.Context, failedSHA256 string) (FetchedToken, error) {
	if f == nil || f.backend == nil || f.Store == nil {
		return FetchedToken{}, errFetchUnavailable
	}
	if token, ok := f.memoryHit(failedSHA256); ok {
		return token, nil
	}
	f.issueMu.Lock()
	defer f.issueMu.Unlock()
	// A concurrent fetch may have refreshed memory while this one waited.
	if token, ok := f.memoryHit(failedSHA256); ok {
		return token, nil
	}
	now := f.now()
	token, present, err := f.backend.readRedis(ctx, now)
	if err != nil {
		return FetchedToken{}, errFetchUnavailable
	}
	if present && token.usable(now) && token.SHA256 != failedSHA256 {
		f.memory.put(token)
		return token.from(FetchSourceRedis), nil
	}
	return f.issueUnderLock(ctx, failedSHA256)
}

func (f *Fetcher) memoryHit(failedSHA256 string) (FetchedToken, bool) {
	current := f.memory.get()
	if !current.usable(f.now()) {
		return FetchedToken{}, false
	}
	if failedSHA256 != "" && failedSHA256 == current.SHA256 {
		return FetchedToken{}, false
	}
	return current.from(FetchSourceMemory), true
}

func (f *Fetcher) issueUnderLock(ctx context.Context, failedSHA256 string) (FetchedToken, error) {
	lockKey := f.backend.redisLockKey()
	lockValue, err := newLockValue()
	if err != nil {
		return FetchedToken{}, errFetchUnavailable
	}
	locked, err := f.Store.SetNX(ctx, lockKey, lockValue, f.backend.redisLockTTL())
	if err != nil {
		return FetchedToken{}, errFetchUnavailable
	}
	if !locked {
		return f.waitForPeer(ctx, failedSHA256)
	}
	defer func() {
		releaseContext, cancel := context.WithTimeout(context.Background(), redisDialTimeout)
		defer cancel()
		_ = f.Store.CompareAndDelete(releaseContext, lockKey, lockValue)
	}()
	// A peer can publish between the first read and the lock. Look again while
	// owning the lock, before contacting the provider.
	now := f.now()
	token, present, err := f.backend.readRedis(ctx, now)
	if err != nil {
		return FetchedToken{}, errFetchUnavailable
	}
	if present && token.usable(now) && token.SHA256 != failedSHA256 {
		f.memory.put(token)
		return token.from(FetchSourceRedis), nil
	}
	issued, err := f.backend.issueAndStore(ctx)
	if err != nil {
		return FetchedToken{}, errFetchUnavailable
	}
	f.memory.put(issued)
	return issued.from(FetchSourceIssued), nil
}

// waitForPeer polls Redis for the lock holder's token. There is no fallback to
// issuing without the lock: a timeout is errFetchUnavailable.
func (f *Fetcher) waitForPeer(ctx context.Context, failedSHA256 string) (FetchedToken, error) {
	poll := f.LockPollEvery
	if poll <= 0 {
		poll = lockPollInterval
	}
	timeout := f.LockWaitTimeout
	if timeout <= 0 {
		timeout = lockWaitTimeout
	}
	if f.InitialLockWait > 0 && !waitContext(ctx, f.InitialLockWait) {
		return FetchedToken{}, errFetchUnavailable
	}
	attempts := int((timeout + poll - 1) / poll)
	if attempts < 1 {
		attempts = 1
	}
	for range attempts {
		now := f.now()
		token, present, err := f.backend.readRedis(ctx, now)
		if err != nil {
			return FetchedToken{}, errFetchUnavailable
		}
		if present && token.usable(now) && token.SHA256 != failedSHA256 {
			f.memory.put(token)
			return token.from(FetchSourceRedis), nil
		}
		if !waitContext(ctx, poll) {
			return FetchedToken{}, errFetchUnavailable
		}
	}
	return FetchedToken{}, errFetchUnavailable
}

// ---- EnsureService backend --------------------------------------------------

func (service *EnsureService) redisLockKey() string        { return service.LockKey }
func (service *EnsureService) redisLockTTL() time.Duration { return lockTTL }

func (service *EnsureService) readRedis(ctx context.Context, _ time.Time) (FetchedToken, bool, error) {
	raw, present, err := service.Store.Get(ctx, service.CacheKey)
	if err != nil {
		return FetchedToken{}, false, errFetchUnavailable
	}
	if !present {
		return FetchedToken{}, false, nil
	}
	token, expiresAt, valid := parseCachedTokenPayload(service.Provider, raw)
	if !valid {
		return FetchedToken{}, false, nil
	}
	return newFetchedToken(token, expiresAt), true, nil
}

// parseCachedTokenPayload applies the same strict shapes the Python writers and
// /ensure use: KIS is access_token, expires_at and optional created_at; Toss is
// exactly access_token and expires_at. Freshness is not decided here.
func parseCachedTokenPayload(provider TokenProvider, raw string) (string, time.Time, bool) {
	fields, valid := strictJSONFields(raw)
	if !valid {
		return "", time.Time{}, false
	}
	switch provider {
	case ProviderToss:
		if len(fields) != 2 {
			return "", time.Time{}, false
		}
	default:
		for key := range fields {
			if key != "access_token" && key != "expires_at" && key != "created_at" {
				return "", time.Time{}, false
			}
		}
	}
	accessTokenRaw, hasAccessToken := fields["access_token"]
	expiresAtRaw, hasExpiresAt := fields["expires_at"]
	if !hasAccessToken || !hasExpiresAt {
		return "", time.Time{}, false
	}
	var accessToken string
	var expiresAt float64
	if json.Unmarshal(accessTokenRaw, &accessToken) != nil || json.Unmarshal(expiresAtRaw, &expiresAt) != nil ||
		accessToken == "" || !safeHeaderText(accessToken) ||
		math.IsNaN(expiresAt) || math.IsInf(expiresAt, 0) || expiresAt <= 0 || expiresAt > 1e11 {
		return "", time.Time{}, false
	}
	seconds, fraction := math.Modf(expiresAt)
	return accessToken, time.Unix(int64(seconds), int64(fraction*float64(time.Second))), true
}

// ---- approval backend -------------------------------------------------------

func (s *approvalService) redisLockKey() string        { return s.lockKey }
func (s *approvalService) redisLockTTL() time.Duration { return approvalLockTTL }

// readRedis reads the raw approval key and its remaining TTL; the expiry is
// now plus that TTL because the Redis value carries no timestamp.
func (s *approvalService) readRedis(ctx context.Context, now time.Time) (FetchedToken, bool, error) {
	raw, present, err := s.store.Get(ctx, s.cacheKey)
	if err != nil {
		return FetchedToken{}, false, errFetchUnavailable
	}
	if !present || strings.TrimSpace(raw) == "" || !safeHeaderText(raw) {
		return FetchedToken{}, false, nil
	}
	ttl, err := s.store.TTL(ctx, s.cacheKey)
	if err != nil {
		return FetchedToken{}, false, errFetchUnavailable
	}
	if ttl <= 0 {
		return FetchedToken{}, false, nil
	}
	return newFetchedToken(raw, now.Add(ttl)), true, nil
}
