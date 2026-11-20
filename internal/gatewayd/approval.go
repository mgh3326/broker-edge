package gatewayd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

const approvalTTL = 23 * time.Hour
const approvalLockTTL = 15 * time.Second

// approvalWaitTimeout is how long an /ensure waiter waits on a held lock. It must
// outlive issueLease: an issuer extends the lock to issueLease just before it calls
// KIS, so a holder that dies then keeps the lock that long. (A variable only so a
// test can shorten it.)
var approvalWaitTimeout = issueLease + 5*time.Second

func isApprovalProvider(p TokenProvider) bool {
	return p == ProviderKISLiveApproval || p == ProviderKISMockApproval
}

type approvalStore interface {
	RedisStore
	// TTL returns the key's remaining lifetime; negative when absent, so one
	// PTTL answers presence and freshness atomically.
	TTL(ctx context.Context, key string) (time.Duration, error)
	// GetWithTTL reads the value and its remaining lifetime atomically.
	// serverExpiryMs is the absolute expiry on the Redis server clock;
	// publication is the attempt id of a marker bound to exactly this record.
	GetWithTTL(ctx context.Context, key string) (value string, ttl time.Duration, serverExpiryMs int64, publication string, present bool, err error)
	// Held reports whether key exists, used to observe the issuance lock.
	Held(ctx context.Context, key string) (bool, error)
}

type approvalService struct {
	store             approvalStore
	config            ProviderConfig
	issuer            OAuthIssuer
	cacheKey, lockKey string
	memory            *tokenMemory
	// now is the clock for expiry bookkeeping only; tests replace it.
	now func() time.Time
}

func newApprovalService(store approvalStore, config ProviderConfig, timeout time.Duration) (*approvalService, error) {
	if store == nil || !isApprovalProvider(config.Provider) || !validProviderConfig(config) {
		return nil, errEnsureUnavailable
	}
	prefix := "kis:websocket:approval_key"
	if config.Provider == ProviderKISMockApproval {
		prefix = "kis_mock:websocket:approval_key"
	}
	return &approvalService{store: store, config: config, issuer: approvalIssuer{config: config, timeout: timeout}, cacheKey: prefix, lockKey: prefix + ":lock", memory: newTokenMemory(), now: time.Now}, nil
}

func (s *approvalService) cachedTTL(ctx context.Context) (time.Duration, error) {
	ttl, err := s.store.TTL(ctx, s.cacheKey)
	if err != nil {
		return 0, errEnsureUnavailable
	}
	return ttl, nil
}
func (s *approvalService) Ensure(ctx context.Context) (EnsureState, error) {
	return s.ensure(ctx, false)
}
func (s *approvalService) EnsureForce(ctx context.Context) (EnsureState, error) {
	return s.ensure(ctx, true)
}
func (s *approvalService) ensure(ctx context.Context, force bool) (EnsureState, error) {
	ttl0, err := s.cachedTTL(ctx)
	if err != nil {
		return "", err
	}
	if ttl0 > tokenExpiryBuffer && !force {
		return EnsureStateFresh, nil
	}
	lock, err := newLockValue()
	if err != nil {
		return "", errEnsureUnavailable
	}
	beforeSetNX := time.Now()
	acquired, err := s.store.SetNX(ctx, s.lockKey, lock, approvalLockTTL)
	if err != nil {
		return "", errEnsureUnavailable
	}
	// Publish evidence is a TTL increase over the previously observed sample:
	// a republish SET resets the expiry to ~approvalTTL, while a record that
	// only decays never moves upward.
	prevTTL := ttl0
	if !acquired {
		// The wait outlives the extended issuance lease so a lock whose holder died
		// before releasing it expires before the waiter gives up.
		deadline := time.NewTimer(approvalWaitTimeout)
		defer deadline.Stop()
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			held, err := s.store.Held(ctx, s.lockKey)
			if err != nil {
				return "", errEnsureUnavailable
			}
			ttl, err := s.cachedTTL(ctx)
			if err != nil {
				return "", err
			}
			if ttl > tokenExpiryBuffer && (!force || ttl > prevTTL) {
				return EnsureStateFresh, nil
			}
			if !held {
				// The holder is gone without evidence of a publish, so it
				// failed before replacing the key. Take over issuance instead
				// of accepting the previous record as a forced refresh.
				beforeSetNX = time.Now()
				reacquired, err := s.store.SetNX(ctx, s.lockKey, lock, approvalLockTTL)
				if err != nil {
					return "", errEnsureUnavailable
				}
				if reacquired {
					break
				}
			}
			prevTTL = ttl
			select {
			case <-ctx.Done():
				return "", errEnsureUnavailable
			case <-deadline.C:
				// A fresh record at the deadline means a refresh completed with a
				// lingering lock, so the wait succeeded; a forced refresh also needs
				// the same publication evidence as in the loop (the TTL moved up),
				// never just "the old key still has time left".
				ttl, err := s.cachedTTL(ctx)
				if err != nil {
					return "", err
				}
				if ttl > tokenExpiryBuffer && (!force || ttl > prevTTL) {
					return EnsureStateFresh, nil
				}
				return "", errLockWaitTimeout
			case <-ticker.C:
			}
		}
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), redisDialTimeout)
		defer cancel()
		_ = s.store.CompareAndDelete(c, s.lockKey, lock)
	}()
	// A publish may have landed between the last Held() observation and our
	// SetNX (or between the first sample and a direct acquire); skip issuance
	// when the TTL moved up in that gap.
	recheckContext, cancelRecheck := context.WithDeadline(ctx, leaseDeadline(beforeSetNX, approvalLockTTL))
	ttl, err := s.cachedTTL(recheckContext)
	cancelRecheck()
	if err != nil {
		return "", err
	}
	if ttl > tokenExpiryBuffer && (!force || ttl > prevTTL) {
		return EnsureStateFresh, nil
	}
	if _, err := s.issueAndStore(ctx, issuanceLock{key: s.lockKey, value: lock, deadline: leaseDeadline(beforeSetNX, approvalLockTTL)}); err != nil {
		return "", errEnsureUnavailable
	}
	return EnsureStateIssued, nil
}

// issueAndStore performs one approval-key issue and writes Redis (raw key,
// 23 h TTL) exactly as /ensure does, plus a publication marker in a sibling key.
// The caller owns lock; see issueAndPublish. The predecessor stays visible until
// replaced (an approval key's replacement does not invalidate it).
func (s *approvalService) issueAndStore(ctx context.Context, lock issuanceLock) (FetchedToken, error) {
	return issueAndPublish(ctx, issuancePlan{
		memory: s.memory, lock: lock, lease: approvalLockTTL, now: s.now, readRedis: s.readRedis,
		extend: func(c context.Context, lease time.Duration) error {
			return s.store.ExtendLockIfHeld(c, lock.key, lock.value, lease)
		},
		issue: func(work context.Context) (issuedToken, error) {
			issued, err := s.issuer.Issue(work, s.config.AppKey, s.config.AppSecret)
			if err != nil || strings.TrimSpace(issued.AccessToken) == "" {
				return issuedToken{}, errEnsureUnavailable
			}
			attempt, err := newLockValue()
			if err != nil {
				return issuedToken{}, errEnsureUnavailable
			}
			token := newFetchedToken(issued.AccessToken, s.now().Add(approvalTTL))
			token.Raw, token.Publication = issued.AccessToken, attempt
			return issuedToken{
				token: token,
				publish: func(c context.Context) error {
					return s.store.SetIfLockHeld(c, lock.key, lock.value, s.cacheKey, issued.AccessToken, approvalTTL, attempt)
				},
				committed: func(stored FetchedToken) bool { return stored.Publication == attempt && stored.SHA256 == token.SHA256 },
			}, nil
		},
	})
}

type approvalIssuer struct {
	config    ProviderConfig
	timeout   time.Duration
	transport http.RoundTripper
}

func (a approvalIssuer) Issue(ctx context.Context, key, secret string) (OAuthToken, error) {
	body, err := json.Marshal(struct {
		Grant  string `json:"grant_type"`
		Key    string `json:"appkey"`
		Secret string `json:"secretkey"`
	}{"client_credentials", key, secret})
	if err != nil {
		return OAuthToken{}, errOAuthFailed
	}
	req, err := newPinnedOAuthRequest(ctx, a.config.Provider, a.config.BaseURL, bytes.NewReader(body))
	if err != nil {
		return OAuthToken{}, errOAuthFailed
	}
	req.Header.Set("content-type", "application/json")
	resp, err := newPinnedOAuthClient(a.transport, a.timeout, a.config.Provider).Do(req)
	if err != nil || resp == nil {
		return OAuthToken{}, errOAuthFailed
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return OAuthToken{}, errOAuthFailed
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, oauthResponseLimit+1))
	if err != nil || len(data) > oauthResponseLimit {
		return OAuthToken{}, errOAuthFailed
	}
	var result struct {
		Key string `json:"approval_key"`
	}
	if json.Unmarshal(data, &result) != nil || strings.TrimSpace(result.Key) == "" {
		return OAuthToken{}, errOAuthFailed
	}
	return OAuthToken{AccessToken: result.Key}, nil
}
