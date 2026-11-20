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
	// ServerExpiryMs is the key's absolute expiry on the Redis server clock, set
	// only for values that carry no timestamp of their own (approval keys). It
	// does not depend on client-side latency, so two reads of an untouched key
	// agree and a republish moves it.
	ServerExpiryMs int64
	// Publication is the attempt id of a gatewayd publication marker bound to
	// exactly this record (approval keys); "" for records written by anyone else.
	Publication string
	// Raw is the exact stored Redis value, used to compare-and-withdraw it.
	Raw string
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

// tokenMemory is one provider's in-process copy of its current token, plus the
// hashes of tokens this process knows the broker has since replaced.
//
// gen advances on every change, so a reader that took a Redis snapshot can tell
// that memory moved while it was reading and must not publish its (possibly
// older) snapshot over a newer token.
type tokenMemory struct {
	mu           sync.Mutex
	token        FetchedToken
	gen          uint64
	revoked      map[string]struct{}
	revokedOrder []string
}

const maxRevokedHashes = 32

func newTokenMemory() *tokenMemory { return &tokenMemory{} }

func (m *tokenMemory) snapshot() (token FetchedToken, gen uint64) {
	if m == nil {
		return FetchedToken{}, 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.token, m.gen
}

// putIssued records a token this process just issued and published to Redis.
func (m *tokenMemory) putIssued(token FetchedToken) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.revoked, token.SHA256)
	m.token = token
	m.gen++
}

// adopt publishes a token read from Redis, but only if memory did not change
// since gen was observed and the token was not replaced by the broker.
func (m *tokenMemory) adopt(token FetchedToken, gen uint64) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gen != gen {
		return false
	}
	if _, revoked := m.revoked[token.SHA256]; revoked {
		return false
	}
	m.token = token
	m.gen++
	return true
}

// revoke marks tokens as replaced by the broker. A revoked token is never
// served from memory and never adopted from Redis, even while Redis still
// advertises it.
func (m *tokenMemory) revoke(hashes ...string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revoked == nil {
		m.revoked = make(map[string]struct{})
	}
	for _, hash := range hashes {
		if hash == "" {
			continue
		}
		if _, known := m.revoked[hash]; !known {
			m.revoked[hash] = struct{}{}
			m.revokedOrder = append(m.revokedOrder, hash)
		}
		if m.token.SHA256 == hash {
			m.token = FetchedToken{}
		}
	}
	m.gen++
	for len(m.revokedOrder) > maxRevokedHashes {
		delete(m.revoked, m.revokedOrder[0])
		m.revokedOrder = m.revokedOrder[1:]
	}
}

func (m *tokenMemory) isRevoked(hash string) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, revoked := m.revoked[hash]
	return revoked
}

// issuanceLock names the Redis lock the caller owns while it issues. deadline is
// the conservative absolute end of the lease, measured from before SET NX was
// sent, minus fetchLeaseMargin: nothing lock-owned may be started, or still be
// running, past it.
type issuanceLock struct {
	key, value string
	deadline   time.Time
}

// leaseDeadline is taken by the caller *before* sending SET NX, so network
// latency to Redis can only shorten the window it believes it has.
func leaseDeadline(beforeSetNX time.Time, lease time.Duration) time.Time {
	margin := fetchLeaseMargin
	if lease <= 2*margin {
		margin = lease / 4
	}
	return beforeSetNX.Add(lease - margin)
}

// fetchBackend is the provider-specific half of a Fetcher: how the existing
// Redis key is read and how the existing issuance path writes it.
type fetchBackend interface {
	// readRedis returns the token currently stored in the provider's existing
	// Redis key. present is false for a missing or malformed value; freshness is
	// the caller's decision.
	readRedis(ctx context.Context, now time.Time) (token FetchedToken, present bool, err error)
	// issueAndStore performs one OAuth issue and writes Redis exactly as
	// /ensure does, while owning lock. It publishes to memory on success.
	issueAndStore(ctx context.Context, lock issuanceLock) (FetchedToken, error)
	redisLockKey() string
	redisLockTTL() time.Duration
}

const (
	// fetchAdoptRetries bounds how often a Redis snapshot is retaken because
	// memory moved underneath it.
	fetchAdoptRetries = 4
	// fetchLeaseMargin keeps the whole lock-owned phase inside the Redis lease.
	fetchLeaseMargin = 2 * time.Second
	// The lock-owned phase is budgeted backwards from the lease deadline: the
	// broker call ends publishReserve+reconcileReserve before it, publish
	// attempts end reconcileReserve before it, and the tail is kept live for
	// confirming an ambiguous publish. minIssueWindow is the least broker time
	// worth starting.
	publishAttempts  = 3
	publishRetryWait = 50 * time.Millisecond
	// serverExpiryTolerance absorbs the millisecond rounding of two server-side
	// expiry computations for an untouched record.
	serverExpiryTolerance = 5 * time.Millisecond
)

// Lease budget slices (variables only so tests can shrink them).
var (
	publishReserve   = 3 * time.Second
	reconcileReserve = 3 * time.Second
	minIssueWindow   = 4 * time.Second
)

var errIssueFailed = errors.New("token issue failed")

// issuedToken is what one broker call produced and how to publish and confirm it.
type issuedToken struct {
	token FetchedToken
	// publish writes the shared record, conditional on still owning the lock.
	publish func(context.Context) error
	// committed reports whether a record read back from Redis is this very
	// publication (used when a publish reply was lost).
	committed func(FetchedToken) bool
}

// issuancePlan is one lock-owned issuance.
type issuancePlan struct {
	memory    *tokenMemory
	lock      issuanceLock
	now       func() time.Time
	readRedis func(context.Context, time.Time) (FetchedToken, bool, error)
	issue     func(context.Context) (issuedToken, error)
	// singleToken marks providers whose broker invalidates the previous token on
	// issue (Toss). Their shared predecessor is withdrawn before the broker is
	// called; withdraw is lock- and record-conditional.
	singleToken bool
	withdraw    func(ctx context.Context, expectedRaw string) error
}

// issueAndPublish is the single issuance path shared by /ensure and /fetch.
//
//   - It never contacts the broker unless the lease, measured from before SET
//     NX, still has room for the broker call, publication and reconciliation.
//   - The broker call is cut off before the publish window, and publish attempts
//     before the reconcile window, so confirming an ambiguous publish always has
//     a live context of its own.
//   - Once it starts, everything runs on a context detached from the caller's
//     cancellation (a disconnecting client cannot strand a rotated token),
//     bounded by the lease deadline.
//   - It will not issue if it cannot read the shared record first.
//   - For a single-token provider the predecessor is withdrawn from Redis (only
//     if it still is exactly the snapshot, and only while the lock is held)
//     before the broker rotates it, and revoked in memory. If anything fails
//     afterwards, Redis holds a miss, never the invalidated token — also after a
//     crash or a Redis outage — and the next request reissues.
//   - A publish whose reply was lost is confirmed by reading the record back;
//     a committed replacement is never removed or reissued.
func issueAndPublish(ctx context.Context, plan issuancePlan) (FetchedToken, error) {
	need := minIssueWindow + publishReserve + reconcileReserve
	if ctx.Err() != nil || time.Until(plan.lock.deadline) < need {
		return FetchedToken{}, errIssueFailed
	}
	work, cancel := context.WithDeadline(context.WithoutCancel(ctx), plan.lock.deadline)
	defer cancel()

	stored, present, err := plan.readRedis(work, plan.now())
	if err != nil || time.Until(plan.lock.deadline) < need {
		return FetchedToken{}, errIssueFailed
	}
	if plan.singleToken {
		if present {
			if err := plan.withdraw(work, stored.Raw); err != nil {
				return FetchedToken{}, errIssueFailed
			}
		}
		replaced := []string{}
		if current, _ := plan.memory.snapshot(); current.SHA256 != "" {
			replaced = append(replaced, current.SHA256)
		}
		if present {
			replaced = append(replaced, stored.SHA256)
		}
		plan.memory.revoke(replaced...)
	}
	brokerCtx, cancelBroker := context.WithDeadline(work, plan.lock.deadline.Add(-publishReserve-reconcileReserve))
	issued, err := plan.issue(brokerCtx)
	cancelBroker()
	if err != nil {
		return FetchedToken{}, errIssueFailed
	}
	publishCtx, cancelPublish := context.WithDeadline(work, plan.lock.deadline.Add(-reconcileReserve))
	defer cancelPublish()
	committed := false
	for attempt := range publishAttempts {
		publishErr := issued.publish(publishCtx)
		if publishErr == nil {
			committed = true
			break
		}
		if errors.Is(publishErr, errLockLost) {
			break
		}
		// The reply may have been lost after Redis committed: look, on the
		// reserved reconcile window, before deciding anything.
		if readBack, found, readErr := plan.readRedis(work, plan.now()); readErr == nil && found && issued.committed(readBack) {
			committed = true
			break
		}
		if attempt == publishAttempts-1 || !waitContext(publishCtx, publishRetryWait) {
			break
		}
	}
	if !committed {
		return FetchedToken{}, errIssueFailed
	}
	plan.memory.putIssued(issued.token)
	return issued.token, nil
}

// Fetcher serves one provider's token from memory, Redis or a fresh issue.
// Issuance is serialised in-process by issueSem and across processes by the
// same Redis lock /ensure uses.
type Fetcher struct {
	Store   RedisStore
	backend fetchBackend
	memory  *tokenMemory
	Now     func() time.Time

	InitialLockWait time.Duration
	LockPollEvery   time.Duration
	LockWaitTimeout time.Duration

	// issueSem admits one issuing/refreshing request at a time; acquiring it
	// honours cancellation, so abandoned requests leave the queue.
	issueSem chan struct{}
}

// NewFetcher builds the /fetch capability for this provider. It shares the
// service's memory so an /ensure-driven issue is visible to /fetch.
func (service *EnsureService) NewFetcher() *Fetcher {
	if service.memory == nil {
		service.memory = newTokenMemory()
	}
	return &Fetcher{
		Store:           service.Store,
		backend:         service,
		memory:          service.memory,
		Now:             service.now,
		InitialLockWait: service.initialLockWait(),
		LockPollEvery:   service.lockPollEvery(),
		LockWaitTimeout: service.lockWaitTimeout(),
		issueSem:        make(chan struct{}, 1),
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
		issueSem:        make(chan struct{}, 1),
	}
}

func (f *Fetcher) now() time.Time {
	if f.Now == nil {
		return time.Now()
	}
	return f.Now()
}

func (f *Fetcher) acquire(ctx context.Context) error {
	select {
	case f.issueSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return errFetchUnavailable
	}
}

func (f *Fetcher) release() { <-f.issueSem }

// Warm loads the provider's token from Redis into memory without ever issuing.
// It is best effort: a Redis error or an unusable value leaves memory empty and
// the first Fetch does the same read.
func (f *Fetcher) Warm(ctx context.Context) {
	if f == nil || f.backend == nil {
		return
	}
	_, gen := f.memory.snapshot()
	now := f.now()
	if token, present, err := f.backend.readRedis(ctx, now); err == nil && present && token.usable(now) {
		f.memory.adopt(token, gen)
	}
}

// Fetch implements the /fetch contract:
//   - no failed hash: serve a token with more than 60 s left, else adopt Redis's,
//     else issue;
//   - failed hash: the report is first bound to the Redis publication it
//     observed (baseline, read before it queues). It is then resolved against
//     the shared record: a different unexpired token is adopted and returned; the
//     same token is reissued once under the lock, unless a newer publication
//     (proved by the record, not by a local counter) already answers it; if Redis
//     holds nothing, a different memory token means the caller was stale.
func (f *Fetcher) Fetch(ctx context.Context, failedSHA256 string) (FetchedToken, error) {
	if f == nil || f.backend == nil || f.Store == nil || f.issueSem == nil {
		return FetchedToken{}, errFetchUnavailable
	}
	var baseline *FetchedToken
	if failedSHA256 == "" {
		if current, _ := f.memory.snapshot(); current.usable(f.now()) {
			return current.from(FetchSourceMemory), nil
		}
	} else {
		stored, present, err := f.backend.readRedis(ctx, f.now())
		if err != nil {
			return FetchedToken{}, errFetchUnavailable
		}
		if present {
			baseline = &stored
		}
	}
	if err := f.acquire(ctx); err != nil {
		return FetchedToken{}, err
	}
	defer f.release()
	token, found, observed, err := f.resolveShared(ctx, failedSHA256, baseline)
	if err != nil {
		return FetchedToken{}, err
	}
	if found {
		return token, nil
	}
	if failedSHA256 != "" {
		now := f.now()
		redisHolds := observed != nil && observed.ExpiresAt.After(now) && !f.memory.isRevoked(observed.SHA256)
		current, _ := f.memory.snapshot()
		if !redisHolds && current.usable(now) && current.SHA256 != failedSHA256 {
			return current.from(FetchSourceMemory), nil
		}
	}
	return f.issueUnderLock(ctx, failedSHA256, baseline)
}

// acceptable decides whether a token read from Redis answers this request.
// Ordinary fetches need more than 60 s; a failure report accepts any unexpired
// token other than the reported one, or the reported one only if the shared
// record was published again after the report's baseline.
func (f *Fetcher) acceptable(token FetchedToken, failedSHA256 string, baseline *FetchedToken, now time.Time) bool {
	if token.Token == "" || f.memory.isRevoked(token.SHA256) {
		return false
	}
	if failedSHA256 == "" {
		return token.usable(now)
	}
	if !token.ExpiresAt.After(now) {
		return false
	}
	if token.SHA256 != failedSHA256 {
		return true
	}
	return publishedSince(baseline, token)
}

// publishedSince reports whether token (same bytes as baseline's) is a later
// publication than baseline (nil: none existed). A gatewayd publication carries a unique marker; for
// anyone else's write only a changed expiry can show it.
func publishedSince(baseline *FetchedToken, token FetchedToken) bool {
	if baseline == nil {
		// The report observed no record at all (for Toss: the predecessor is
		// withdrawn while a rotation is in flight), so any record present now was
		// published after it.
		return true
	}
	if token.Publication != "" {
		return token.Publication != baseline.Publication
	}
	if token.ServerExpiryMs != 0 && baseline.ServerExpiryMs != 0 {
		return token.ServerExpiryMs > baseline.ServerExpiryMs+serverExpiryTolerance.Milliseconds()
	}
	return token.ExpiresAt.After(baseline.ExpiresAt)
}

// resolveShared answers from state somebody else already produced: memory (plain
// fetches only) or Redis. found is false when nothing acceptable exists;
// observed is the Redis token seen, if any.
func (f *Fetcher) resolveShared(ctx context.Context, failedSHA256 string, baseline *FetchedToken) (token FetchedToken, found bool, observed *FetchedToken, err error) {
	for range fetchAdoptRetries {
		current, gen := f.memory.snapshot()
		now := f.now()
		if current.usable(now) && failedSHA256 == "" {
			return current.from(FetchSourceMemory), true, observed, nil
		}
		stored, present, readErr := f.backend.readRedis(ctx, now)
		if readErr != nil {
			return FetchedToken{}, false, nil, errFetchUnavailable
		}
		// Judge remaining lifetime at the end of the read, not before it.
		now = f.now()
		observed = nil
		if present {
			copied := stored
			observed = &copied
		}
		if !present || !f.acceptable(stored, failedSHA256, baseline, now) {
			return FetchedToken{}, false, observed, nil
		}
		if f.memory.adopt(stored, gen) {
			return stored.from(FetchSourceRedis), true, observed, nil
		}
		// Memory moved while Redis was being read (an /ensure publish): the
		// snapshot may be the token that publish replaced. Look again.
	}
	return FetchedToken{}, false, nil, errFetchUnavailable
}

func (f *Fetcher) issueUnderLock(ctx context.Context, failedSHA256 string, baseline *FetchedToken) (FetchedToken, error) {
	lock := issuanceLock{key: f.backend.redisLockKey()}
	value, err := newLockValue()
	if err != nil {
		return FetchedToken{}, errFetchUnavailable
	}
	lock.value = value
	beforeSetNX := time.Now()
	locked, err := f.Store.SetNX(ctx, lock.key, lock.value, f.backend.redisLockTTL())
	if err != nil {
		return FetchedToken{}, errFetchUnavailable
	}
	if !locked {
		return f.waitForPeer(ctx, failedSHA256, baseline)
	}
	defer func() {
		releaseContext, cancel := context.WithTimeout(context.Background(), redisDialTimeout)
		defer cancel()
		_ = f.Store.CompareAndDelete(releaseContext, lock.key, lock.value)
	}()
	// A peer can publish between the first read and the lock. Look again while
	// owning the lock, before contacting the provider.
	lock.deadline = leaseDeadline(beforeSetNX, f.backend.redisLockTTL())
	recheckCtx, cancelRecheck := context.WithDeadline(ctx, lock.deadline)
	token, found, _, err := f.resolveShared(recheckCtx, failedSHA256, baseline)
	cancelRecheck()
	if err != nil {
		return FetchedToken{}, err
	}
	if found {
		return token, nil
	}
	issued, err := f.backend.issueAndStore(ctx, lock)
	if err != nil {
		return FetchedToken{}, errFetchUnavailable
	}
	return issued.from(FetchSourceIssued), nil
}

// waitForPeer polls for the lock holder's publication. There is no fallback to
// issuing without the lock: a timeout is errFetchUnavailable.
func (f *Fetcher) waitForPeer(ctx context.Context, failedSHA256 string, baseline *FetchedToken) (FetchedToken, error) {
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
		token, found, _, err := f.resolveShared(ctx, failedSHA256, baseline)
		if err != nil {
			return FetchedToken{}, err
		}
		if found {
			return token, nil
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
	fetched := newFetchedToken(token, expiresAt)
	fetched.Raw = raw
	return fetched, true, nil
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

// readRedis reads the raw approval key, its remaining TTL and its absolute
// server-side expiry in one atomic Redis operation; the local expiry is now plus
// that TTL because the Redis value carries no timestamp. Two separate reads
// could pair one key with the fresh TTL of its replacement.
func (s *approvalService) readRedis(ctx context.Context, now time.Time) (FetchedToken, bool, error) {
	raw, ttl, serverExpiryMs, publication, present, err := s.store.GetWithTTL(ctx, s.cacheKey)
	if err != nil {
		return FetchedToken{}, false, errFetchUnavailable
	}
	if !present || strings.TrimSpace(raw) == "" || !safeHeaderText(raw) || ttl <= 0 {
		return FetchedToken{}, false, nil
	}
	token := newFetchedToken(raw, now.Add(ttl))
	token.ServerExpiryMs = serverExpiryMs
	token.Publication = publication
	token.Raw = raw
	return token, true, nil
}
