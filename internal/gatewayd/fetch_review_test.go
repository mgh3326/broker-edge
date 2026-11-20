package gatewayd

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

const (
	externalA = "EXTERNAL-ISSUER-A-0123456789abcdef"
	externalB = "EXTERNAL-ISSUER-B-0123456789abcdef"
	sameToken = "PROVIDER-REUSES-THIS-TOKEN-0123456789"
)

// An /ensure publish that lands while /fetch is reading Redis must not be
// rolled back by the older value /fetch read.
func TestFetchAdoptionNeverRollsBackAConcurrentEnsurePublish(t *testing.T) {
	h := newFetchHarness(t, ProviderToss)
	h.writeRedis(externalA, 90) // inside /ensure's 120 s window, usable for /fetch
	h.store.onNextGet(func() {
		if state, err := h.ensurer.Ensure(context.Background()); err != nil || state != EnsureStateIssued {
			t.Errorf("concurrent ensure = %s %v", state, err)
		}
	})
	got := h.fetch("")
	if got.Token != tokenN(1) {
		t.Fatalf("fetch returned %q-source token, want the ensure-issued one", got.Source)
	}
	for range 3 {
		if again := h.fetch(""); again.Token != tokenN(1) || again.Source != FetchSourceMemory {
			t.Fatalf("memory was rolled back to an older token (source %s)", again.Source)
		}
	}
	if h.issuer.callCount() != 1 {
		t.Fatalf("issuer calls = %d", h.issuer.callCount())
	}
}

// If the broker replaced token A but Redis could not be updated, A must not be
// served again from memory or re-adopted from Redis.
func TestFetchRedisWriteFailureAfterRotationNeverServesTheReplacedToken(t *testing.T) {
	t.Run("fetch-triggered", func(t *testing.T) {
		h := newFetchHarness(t, ProviderToss)
		first := h.fetch("")
		h.store.setErr = errors.New("redis write failed")
		if _, err := h.fetcher.Fetch(context.Background(), first.SHA256); err == nil {
			t.Fatal("expected failure")
		}
		h.store.setErr = nil
		got := h.fetch("")
		if got.Token == first.Token || got.Source != FetchSourceIssued || got.Token != tokenN(3) {
			t.Fatalf("served %s token after rotation (calls %d)", got.Source, h.issuer.callCount())
		}
		if again := h.fetch(""); again.Token != tokenN(3) || again.Source != FetchSourceMemory {
			t.Fatal("recovered token not in memory")
		}
	})
	t.Run("ensure-triggered", func(t *testing.T) {
		h := newFetchHarness(t, ProviderToss)
		h.writeRedis(externalA, 90) // within /ensure's rotation window
		h.fetcher.Warm(context.Background())
		if got := h.fetch(""); got.Token != externalA {
			t.Fatalf("setup: %s", got.Source)
		}
		h.store.setErr = errors.New("redis write failed")
		if _, err := h.ensurer.Ensure(context.Background()); err == nil {
			t.Fatal("expected ensure failure")
		}
		h.store.setErr = nil
		got := h.fetch("")
		if got.Token == externalA || got.Source != FetchSourceIssued {
			t.Fatalf("served the replaced token (source %s)", got.Source)
		}
	})
}

// A client that disconnects after the broker rotated the token must not leave
// Redis holding the revoked one.
func TestFetchIssuanceCompletesAfterCallerCancels(t *testing.T) {
	h := newFetchHarness(t, ProviderToss)
	h.issuer.started = make(chan struct{}, 1)
	h.issuer.release = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = h.fetcher.Fetch(ctx, "")
	}()
	<-h.issuer.started
	cancel()
	close(h.issuer.release)
	<-done
	if records := h.store.savedRecords(); len(records) != 1 {
		t.Fatalf("Redis writes after caller cancel = %d, want the rotated token published", len(records))
	}
	if got := h.fetch(""); got.Source != FetchSourceMemory || got.Token != tokenN(1) {
		t.Fatalf("after cancel: %s", got.Source)
	}
}

func TestFetchIssuanceDoesNotStartForACancelledCaller(t *testing.T) {
	h := newFetchHarness(t, ProviderToss)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.fetcher.Fetch(ctx, ""); err == nil || h.issuer.callCount() != 0 {
		t.Fatalf("err %v calls %d", err, h.issuer.callCount())
	}
}

func TestFetchIssuancePhaseIsBoundedByTheLockLease(t *testing.T) {
	for _, provider := range fetchProviders {
		t.Run(string(provider), func(t *testing.T) {
			h := newFetchHarness(t, provider)
			h.fetch("")
			lease := lockTTL
			if isApprovalProvider(provider) {
				lease = approvalLockTTL
			}
			h.issuer.mu.Lock()
			deadline := h.issuer.deadline
			h.issuer.mu.Unlock()
			if remaining := time.Until(deadline); deadline.IsZero() || remaining <= 0 || remaining > lease-fetchLeaseMargin {
				t.Fatalf("issuer deadline in %v, want within (0, %v]", remaining, lease-fetchLeaseMargin)
			}
		})
	}
}

// An issuer whose lease was taken over while the broker call was in flight must
// not overwrite the successor's publication.
func TestFetchLateIssuerCannotOverwriteASuccessor(t *testing.T) {
	for _, provider := range []TokenProvider{ProviderToss, ProviderKISLiveApproval} {
		t.Run(string(provider), func(t *testing.T) {
			h := newFetchHarness(t, provider)
			h.issuer.started = make(chan struct{}, 1)
			h.issuer.release = make(chan struct{})
			result := make(chan error, 1)
			go func() {
				_, err := h.fetcher.Fetch(context.Background(), "")
				result <- err
			}()
			<-h.issuer.started
			h.store.mu.Lock()
			h.store.locks[h.lockKey] = storedValue{value: "successor-lock", expiresAt: h.now.Add(time.Minute)}
			h.store.mu.Unlock()
			close(h.issuer.release)
			if err := <-result; err == nil {
				t.Fatal("expected failure after losing the lock")
			}
			if records := h.store.savedRecords(); len(records) != 0 {
				t.Fatalf("late issuer wrote Redis: %d records", len(records))
			}
		})
	}
}

// The approval key and its TTL come from one atomic Redis operation.
func TestApprovalFetchReadsValueAndTTLAtomically(t *testing.T) {
	h := newFetchHarness(t, ProviderKISLiveApproval)
	h.fetch("")
	h.store.fakeRedisStore.save(h.cacheKey, "approval-from-elsewhere", approvalTTL)
	restarted := newFetchHarness(t, ProviderKISLiveApproval)
	restarted.store.fakeRedisStore = h.store.fakeRedisStore
	restarted.attach(restarted.store)
	restarted.fetcher.Warm(context.Background())
	restarted.fetch("")
	restarted.fetch(sha("x"))
	if n := restarted.store.separateReads.Load() + h.store.separateReads.Load(); n != 0 {
		t.Fatalf("approval fetch used %d separate GET/PTTL reads", n)
	}
	if restarted.store.reads.Load() == 0 {
		t.Fatal("approval fetch never read Redis")
	}
}

// Overlapping failure reports share one refresh even when the provider returns
// the same token bytes again.
func TestFetchOverlappingReportsShareARefreshThatReturnsTheSameToken(t *testing.T) {
	for _, provider := range []TokenProvider{ProviderToss, ProviderKISMock, ProviderKISLiveApproval} {
		t.Run(string(provider), func(t *testing.T) {
			h := newFetchHarness(t, provider)
			h.issuer.tokenFn = func(int) string { return sameToken }
			first := h.fetch("")
			// Hold the refresh open so every report is in flight before it completes
			// (a report arriving after it would be a genuine second failure).
			h.issuer.started = make(chan struct{}, 1)
			h.issuer.release = make(chan struct{})
			var wg sync.WaitGroup
			for range 12 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if got, err := h.fetcher.Fetch(context.Background(), first.SHA256); err != nil || got.Token != sameToken {
						t.Errorf("fetch: %v", err)
					}
				}()
			}
			<-h.issuer.started
			time.Sleep(100 * time.Millisecond)
			close(h.issuer.release)
			wg.Wait()
			if h.issuer.callCount() != 2 {
				t.Fatalf("issuer calls = %d, want 2 (one refresh for all reports)", h.issuer.callCount())
			}
		})
	}
}

// A peer process that republishes the same approval key (TTL reset) answers a
// waiting report instead of timing out.
func TestFetchPeerRepublishOfTheSameValueAnswersAWaitingReport(t *testing.T) {
	a := newFetchHarness(t, ProviderKISLiveApproval)
	a.issuer.tokenFn = func(int) string { return sameToken }
	first := a.fetch("")
	a.now = a.now.Add(10 * time.Minute)
	b := newFetchHarness(t, ProviderKISLiveApproval)
	b.store.fakeRedisStore = a.store.fakeRedisStore
	b.issuer = a.issuer
	b.now = a.now.Add(-10 * time.Minute) // b's clock lags until the republish
	b.attach(b.store)
	b.fetcher.LockWaitTimeout = 5 * time.Second
	b.fetcher.Now = func() time.Time { return a.now }

	a.issuer.started = make(chan struct{}, 1)
	a.issuer.release = make(chan struct{})
	aDone := make(chan error, 1)
	go func() {
		_, err := a.fetcher.Fetch(context.Background(), first.SHA256)
		aDone <- err
	}()
	<-a.issuer.started
	bResult := make(chan FetchedToken, 1)
	go func() {
		got, err := b.fetcher.Fetch(context.Background(), first.SHA256)
		if err != nil {
			t.Errorf("waiting report failed: %v", err)
		}
		bResult <- got
	}()
	deadline := time.After(2 * time.Second)
	for b.store.lockAttempts() < 3 { // a's lock, b's refused attempt (plus the initial fetch's)
		select {
		case <-deadline:
			t.Fatal("peer never reached the lock")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	close(a.issuer.release)
	if err := <-aDone; err != nil {
		t.Fatal(err)
	}
	if got := <-bResult; got.Token != sameToken || got.Source != FetchSourceRedis {
		t.Fatalf("peer answer = %s", got.Source)
	}
	if a.issuer.callCount() != 2 {
		t.Fatalf("issuer calls = %d", a.issuer.callCount())
	}
}

func TestFetchFailureReportAdoptsADifferentTokenWithLessThanAMinuteLeft(t *testing.T) {
	h := newFetchHarness(t, ProviderToss)
	first := h.fetch("")
	h.writeRedis(externalB, 30)
	got := h.fetch(first.SHA256)
	if got.Source != FetchSourceRedis || got.Token != externalB || h.issuer.callCount() != 1 {
		t.Fatalf("report with short-lived different Redis token: source %s, issuer calls %d", got.Source, h.issuer.callCount())
	}
}

// A report is resolved against the shared Redis value, not against a memory
// copy that another issuer may already have replaced.
func TestFetchFailureReportIsResolvedAgainstRedisNotStaleMemory(t *testing.T) {
	t.Run("report names the current Redis token", func(t *testing.T) {
		h := newFetchHarness(t, ProviderToss)
		h.fetch("") // memory holds the gateway's own token
		h.writeRedis(externalB, 3600)
		got := h.fetch(sha(externalB)) // the consumer got B elsewhere and B was refused
		if got.Source != FetchSourceIssued || got.Token == externalB {
			t.Fatalf("report for the current Redis token returned %s", got.Source)
		}
		if h.issuer.callCount() != 2 {
			t.Fatalf("issuer calls = %d", h.issuer.callCount())
		}
	})
	t.Run("report names an older token", func(t *testing.T) {
		h := newFetchHarness(t, ProviderToss)
		h.fetch("")
		h.writeRedis(externalB, 3600)
		got := h.fetch(sha("a-token-older-than-both"))
		if got.Token != externalB || got.Source != FetchSourceRedis || h.issuer.callCount() != 1 {
			t.Fatalf("stale report answered with %s", got.Source)
		}
	})
}
