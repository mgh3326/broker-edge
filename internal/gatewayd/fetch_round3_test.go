package gatewayd

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// For a single-token provider the shared predecessor must already be a miss
// when the broker is called: a crash or a Redis outage after rotation can then
// never leave the invalidated token readable.
func TestTossPredecessorIsWithdrawnFromRedisBeforeTheBrokerIsCalled(t *testing.T) {
	h := newFetchHarness(t, ProviderToss)
	first := h.fetch("")
	var presentAtBroker bool
	h.issuer.onIssue = func() {
		_, presentAtBroker, _ = h.store.Get(context.Background(), h.cacheKey)
	}
	h.fetch(first.SHA256)
	if presentAtBroker {
		t.Fatal("the predecessor was still readable in Redis while the broker rotated it")
	}
	if len(h.store.deletes) != 1 {
		t.Fatalf("withdrawals = %v", h.store.deletes)
	}
}

func TestWithdrawalIsRecordConditional(t *testing.T) {
	h := newFetchHarness(t, ProviderToss)
	h.fetch("")
	// Someone replaced the record between the snapshot and the withdrawal: it must
	// not be withdrawn, and the broker must not be called.
	service := h.ensurer.(*EnsureService)
	lock := issuanceLock{key: h.lockKey, value: "owner", deadline: time.Now().Add(time.Minute)}
	h.store.mu.Lock()
	h.store.locks[h.lockKey] = storedValue{value: "owner", expiresAt: h.now.Add(time.Minute)}
	h.store.mu.Unlock()
	h.store.onNextGet(func() { h.writeRedis(externalB, 3600) })
	calls := h.issuer.callCount()
	if _, err := service.issueAndStore(context.Background(), lock); err == nil {
		t.Fatal("issuance proceeded although the record changed under it")
	}
	if h.issuer.callCount() != calls {
		t.Fatal("the broker was called after a failed withdrawal")
	}
	if got, _, _ := h.store.Get(context.Background(), h.cacheKey); got == "" {
		t.Fatal("a record the issuer did not snapshot was withdrawn")
	}
}

// Publication gets an earlier deadline than reconciliation: a publish that stalls
// to its deadline still leaves a live context to look the record up on.
func TestIssuanceReconcilesOnItsOwnLiveContextAfterAStalledPublish(t *testing.T) {
	defer func(a, b, c time.Duration) { publishReserve, reconcileReserve, minIssueWindow = a, b, c }(publishReserve, reconcileReserve, minIssueWindow)
	publishReserve, reconcileReserve, minIssueWindow = 50*time.Millisecond, 400*time.Millisecond, 10*time.Millisecond

	memory := newTokenMemory()
	token := newFetchedToken("RECONCILED-TOKEN-0123456789", time.Unix(2_000_003_600, 0))
	var reconcileCtxErr error
	reads := 0
	plan := issuancePlan{
		memory: memory,
		lock:   issuanceLock{key: "lock", value: "owner", deadline: time.Now().Add(1200 * time.Millisecond)},
		now:    testGatewayNow,
		readRedis: func(ctx context.Context, _ time.Time) (FetchedToken, bool, error) {
			reads++
			if reads == 1 {
				return FetchedToken{}, false, nil // snapshot: nothing there
			}
			reconcileCtxErr = ctx.Err() // the read-back after the stalled publish
			stored := token
			stored.Raw = "committed"
			return stored, true, nil
		},
		issue: func(context.Context) (issuedToken, error) {
			return issuedToken{
				token: token,
				publish: func(ctx context.Context) error {
					<-ctx.Done() // the Redis write stalls until the publish deadline
					return ctx.Err()
				},
				committed: func(stored FetchedToken) bool { return stored.Raw == "committed" },
			}, nil
		},
	}
	got, err := issueAndPublish(context.Background(), plan)
	if err != nil || got.Token != token.Token {
		t.Fatalf("issueAndPublish = %v", err)
	}
	if reconcileCtxErr != nil {
		t.Fatalf("the read-back ran on a dead context: %v", reconcileCtxErr)
	}
	if current, _ := memory.snapshot(); current.Token != token.Token {
		t.Fatal("a confirmed publication did not reach memory")
	}
}

// A publish whose reply was lost after Redis committed is a success: the
// replacement stays, and no second broker call is made for it.
func TestCommittedPublishWithALostReplyIsKeptNotWithdrawnOrReissued(t *testing.T) {
	for _, provider := range []TokenProvider{ProviderToss, ProviderKISLiveApproval} {
		t.Run(string(provider), func(t *testing.T) {
			h := newFetchHarness(t, provider)
			first := h.fetch("")
			h.store.fakeRedisStore.lostReply = true
			got := h.fetch(first.SHA256)
			if got.Source != FetchSourceIssued || got.Token != tokenN(2) || h.issuer.callCount() != 2 {
				t.Fatalf("source %s, issuer calls %d", got.Source, h.issuer.callCount())
			}
			if stored, present, _ := h.store.Get(context.Background(), h.cacheKey); !present || stored == "" {
				t.Fatal("the committed replacement was removed")
			}
			if again := h.fetch(""); again.Token != tokenN(2) || again.Source != FetchSourceMemory {
				t.Fatalf("after the lost reply: %s", again.Source)
			}
			wantWithdrawals := 0
			if provider == ProviderToss {
				wantWithdrawals = 1 // the predecessor, before the broker call; nothing after
			}
			if len(h.store.deletes) != wantWithdrawals {
				t.Fatalf("withdrawals = %v", h.store.deletes)
			}
		})
	}
}

// A report for B that is first seen after B reached Redis but before this process
// recorded it in memory is a report about B's publication: B is not an answer.
func TestFetchReportForAJustPublishedTokenIsNotAnsweredWithThatToken(t *testing.T) {
	h := newFetchHarness(t, ProviderToss)
	first := h.fetch("")
	var wg sync.WaitGroup
	var second FetchedToken
	var secondErr error
	h.store.afterSetHook = func() {
		// B is in Redis; memory does not know it yet. A consumer reads and reports B.
		wg.Add(1)
		go func() {
			defer wg.Done()
			second, secondErr = h.fetcher.Fetch(context.Background(), sha(tokenN(2)))
		}()
		time.Sleep(150 * time.Millisecond) // the report has taken its baseline and queued
	}
	got := h.fetch(first.SHA256)
	wg.Wait()
	if got.Token != tokenN(2) {
		t.Fatalf("first refresh = %s", got.Source)
	}
	if secondErr != nil {
		t.Fatal(secondErr)
	}
	if second.Token == tokenN(2) || second.Source != FetchSourceIssued {
		t.Fatalf("a report for B was answered with B (source %s)", second.Source)
	}
}

func TestPublishedSince(t *testing.T) {
	at := func(ms int64) FetchedToken {
		token := newFetchedToken("same-bytes-0123456789", time.Unix(2_000_000_000, 0).Add(time.Duration(ms)*time.Millisecond))
		return token
	}
	baseline := at(0)
	approvalBase := baseline
	approvalBase.ServerExpiryMs = 1_000_000
	withMarker := func(base FetchedToken, marker string) FetchedToken { base.Publication = marker; return base }
	later := func(base FetchedToken, ms int64) FetchedToken {
		base.ExpiresAt = base.ExpiresAt.Add(time.Duration(ms) * time.Millisecond)
		if base.ServerExpiryMs != 0 {
			base.ServerExpiryMs += ms
		}
		return base
	}
	for name, c := range map[string]struct {
		baseline *FetchedToken
		token    FetchedToken
		want     bool
	}{
		"no baseline: nothing existed":                       {nil, baseline, true},
		"same payload expiry: untouched":                     {&baseline, baseline, false},
		"payload expiry later by 1 ms":                       {&baseline, later(baseline, 1), true},
		"approval, untouched, jitter below tolerance":        {&approvalBase, later(approvalBase, 3), false},
		"approval, legacy rewrite 400 ms later":              {&approvalBase, later(approvalBase, 400), true},
		"approval, marker where the baseline had none":       {&approvalBase, withMarker(approvalBase, "m1"), true},
		"approval, new marker, identical expiry (same tick)": {ptr(withMarker(approvalBase, "m1")), withMarker(approvalBase, "m2"), true},
		"approval, same marker, identical expiry":            {ptr(withMarker(approvalBase, "m1")), withMarker(approvalBase, "m1"), false},
	} {
		if got := publishedSince(c.baseline, c.token); got != c.want {
			t.Errorf("%s: publishedSince = %t, want %t", name, got, c.want)
		}
	}
}

func ptr(token FetchedToken) *FetchedToken { return &token }

// An abandoned request leaves the issuance queue instead of waiting behind
// slow Redis or broker work.
func TestFetchQueuedRequestLeavesTheQueueWhenItsContextIsCancelled(t *testing.T) {
	h := newFetchHarness(t, ProviderToss)
	h.issuer.started = make(chan struct{}, 1)
	h.issuer.release = make(chan struct{})
	go func() { _, _ = h.fetcher.Fetch(context.Background(), "") }()
	waitStarted(t, h.issuer.started)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := h.fetcher.Fetch(ctx, "")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errFetchUnavailable) {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a cancelled request stayed queued behind the issuance")
	}
	if h.issuer.callCount() != 1 {
		t.Fatalf("issuer calls = %d", h.issuer.callCount())
	}
}

// An /ensure-driven Toss rotation also withdraws the predecessor before the call.
func TestEnsureWithdrawsTheTossPredecessorBeforeRotation(t *testing.T) {
	h := newFetchHarness(t, ProviderToss)
	h.writeRedis(externalA, 90) // inside /ensure's rotation window
	var presentAtBroker bool
	h.issuer.onIssue = func() { _, presentAtBroker, _ = h.store.Get(context.Background(), h.cacheKey) }
	if _, err := h.ensurer.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if presentAtBroker {
		t.Fatal("ensure rotated a token that was still readable in Redis")
	}
}

// The lease budget must leave the broker its configured HTTP timeout (10 s by
// default): a 15 s approval lease cannot spend most of itself on reserves.
func TestIssuanceLeavesTheBrokerItsFullHTTPTimeout(t *testing.T) {
	const brokerHTTPTimeout = 10 * time.Second
	for _, provider := range fetchProviders {
		t.Run(string(provider), func(t *testing.T) {
			h := newFetchHarness(t, provider)
			start := time.Now()
			h.fetch("")
			h.issuer.mu.Lock()
			deadline := h.issuer.deadline
			h.issuer.mu.Unlock()
			if room := deadline.Sub(start); room < brokerHTTPTimeout {
				t.Fatalf("the broker call is cut off after %v, shorter than its %v timeout", room, brokerHTTPTimeout)
			}
		})
	}
}

// A Redis miss is not evidence that a Toss memory token is current: a peer's
// rotation withdraws the key first, and the memory token may already be
// replaced. Such reports go through the lock instead of being answered from memory.
func TestTossFailureReportOnARedisMissDoesNotReturnTheMemoryToken(t *testing.T) {
	setup := func(t *testing.T, provider TokenProvider) (*fetchHarness, FetchedToken) {
		h := newFetchHarness(t, provider)
		held := h.fetch("") // memory holds X
		// A peer replaced X with Y, handed Y out, and is now rotating Y: it has
		// withdrawn the shared key and holds the issuance lock.
		h.store.mu.Lock()
		delete(h.store.values, h.cacheKey)
		h.store.mu.Unlock()
		return h, held
	}
	t.Run("peer holds the lock: wait, never the memory token", func(t *testing.T) {
		h, held := setup(t, ProviderToss)
		h.store.mu.Lock()
		h.store.locks[h.lockKey] = storedValue{value: "peer", expiresAt: h.now.Add(time.Minute)}
		h.store.mu.Unlock()
		got, err := h.fetcher.Fetch(context.Background(), sha("Y-handed-out-by-the-peer"))
		if err == nil {
			t.Fatalf("answered from %s with the replaced token (%v)", got.Source, got.Token == held.Token)
		}
		if h.issuer.callCount() != 1 {
			t.Fatal("issued while a peer held the lock")
		}
	})
	t.Run("peer published: its token is returned", func(t *testing.T) {
		h, held := setup(t, ProviderToss)
		h.store.mu.Lock()
		h.store.locks[h.lockKey] = storedValue{value: "peer", expiresAt: h.now.Add(time.Minute)}
		h.store.mu.Unlock()
		h.fetcher.LockWaitTimeout = 2 * time.Second
		go func() {
			time.Sleep(50 * time.Millisecond)
			h.writeRedis(externalB, 3600)
		}()
		got, err := h.fetcher.Fetch(context.Background(), sha("Y-handed-out-by-the-peer"))
		if err != nil || got.Token != externalB || got.Token == held.Token {
			t.Fatalf("got %s %v", got.Source, err)
		}
	})
	t.Run("no peer rotation: recover under the lock", func(t *testing.T) {
		h, held := setup(t, ProviderToss)
		got := h.fetch(sha("Y-handed-out-by-the-peer"))
		if got.Source != FetchSourceIssued || got.Token == held.Token {
			t.Fatalf("source %s", got.Source)
		}
	})
	t.Run("providers whose issue invalidates nothing keep the memory answer", func(t *testing.T) {
		h, held := setup(t, ProviderKISMock)
		got := h.fetch(sha("a-token-this-caller-held"))
		if got.Source != FetchSourceMemory || got.Token != held.Token || h.issuer.callCount() != 1 {
			t.Fatalf("source %s", got.Source)
		}
	})
}

// The broker gets its full HTTP timeout measured from the moment it is called,
// not from before the Redis phases (SET NX, recheck, snapshot) that precede it.
func TestBrokerDeadlineIsMeasuredAtIssueEntryUnderSlowRedis(t *testing.T) {
	const brokerHTTPTimeout = 10 * time.Second
	for _, provider := range []TokenProvider{ProviderKISLiveApproval, ProviderToss} {
		t.Run(string(provider), func(t *testing.T) {
			h := newFetchHarness(t, provider)
			first := h.fetch("")
			h.store.getDelay, h.store.setNXDelay = 400*time.Millisecond, 400*time.Millisecond
			h.fetch(first.SHA256) // baseline read, SET NX, recheck read, snapshot read: ~400 ms each
			h.issuer.mu.Lock()
			room := h.issuer.deadline.Sub(h.issuer.enteredAt)
			h.issuer.mu.Unlock()
			if room < brokerHTTPTimeout {
				t.Fatalf("the broker had %v at entry, less than its %v timeout", room, brokerHTTPTimeout)
			}
			if isApprovalProvider(provider) {
				if len(h.store.extensions) != 2 || h.store.extensions[1] != issueLease {
					t.Fatalf("approval lock extensions = %v", h.store.extensions)
				}
			} else if len(h.store.extensions) != 0 {
				t.Fatalf("%s lock was extended: %v", provider, h.store.extensions)
			}
		})
	}
}

// Uncertain ownership of the lock means no broker call.
func TestApprovalIssuanceDoesNotCallTheBrokerWhenTheLockCannotBeExtended(t *testing.T) {
	h := newFetchHarness(t, ProviderKISLiveApproval)
	h.store.extendErr = errors.New("redis unavailable")
	if _, err := h.fetcher.Fetch(context.Background(), ""); err == nil || h.issuer.callCount() != 0 {
		t.Fatalf("err %v, issuer calls %d", err, h.issuer.callCount())
	}
}

// After the lease is extended, a read-back of a publish whose reply stalled until
// its deadline still gets a full Redis dial's worth of time.
func TestReadBackAfterAStalledPublishKeepsAFullRedisDialOnAnExtendedLease(t *testing.T) {
	var publishDeadline, readBackDeadline time.Time
	reads := 0
	token := newFetchedToken("EXTENDED-LEASE-TOKEN-0123456789", time.Unix(2_000_003_600, 0))
	plan := issuancePlan{
		memory: newTokenMemory(),
		lock:   issuanceLock{key: "lock", value: "owner", deadline: time.Now().Add(13 * time.Second)},
		lease:  approvalLockTTL,
		now:    testGatewayNow,
		extend: func(context.Context, time.Duration) error { return nil },
		readRedis: func(ctx context.Context, _ time.Time) (FetchedToken, bool, error) {
			reads++
			if reads == 1 {
				return FetchedToken{}, false, nil
			}
			readBackDeadline, _ = ctx.Deadline()
			stored := token
			stored.Raw = "committed"
			return stored, true, nil
		},
		issue: func(context.Context) (issuedToken, error) {
			return issuedToken{
				token: token,
				publish: func(ctx context.Context) error {
					publishDeadline, _ = ctx.Deadline()
					return errors.New("reply lost")
				},
				committed: func(stored FetchedToken) bool { return stored.Raw == "committed" },
			}, nil
		},
	}
	if _, err := issueAndPublish(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if room := readBackDeadline.Sub(publishDeadline); room < redisDialTimeout {
		t.Fatalf("the read-back window after the publish deadline is %v, shorter than one Redis dial (%v)", room, redisDialTimeout)
	}
}
