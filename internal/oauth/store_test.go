// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package oauth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SukramJ/ha-airlock/internal/audit"
	"github.com/SukramJ/ha-airlock/internal/oauth"
	"github.com/SukramJ/ha-airlock/internal/policy"
)

const (
	clientID    = "https://client.example/metadata.json"
	redirectURI = "http://127.0.0.1:33418/callback"
	resource    = "https://airlock.example/mcp"
	verifier    = "a-code-verifier-that-is-long-enough-for-pkce-0123456789"
	admin       = "home-assistant-user-id-of-the-admin"
)

func challengeOf(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func request() *oauth.Request {
	return &oauth.Request{
		ClientID: clientID, ClientName: "Test Client", RedirectURI: redirectURI,
		State: "state-1", Challenge: challengeOf(verifier), Resource: resource,
	}
}

// clock is a settable time source.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type fixture struct {
	store     *oauth.Store
	clock     *clock
	dir       string
	auditPath string
	auditLog  *audit.Log
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{dir: dir, auditPath: filepath.Join(dir, "audit.jsonl"), clock: &clock{now: time.Unix(1_800_000_000, 0)}}
	log, err := audit.Open(f.auditPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	f.auditLog = log
	f.open(t)
	return f
}

// open (re)opens the store on the fixture's directory.
func (f *fixture) open(t *testing.T) {
	t.Helper()
	store, err := oauth.Open(filepath.Join(f.dir, "grants.json"), f.auditLog)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	store.SetClock(f.clock.Now)
	f.store = store
}

func (f *fixture) auditText(t *testing.T) string {
	t.Helper()
	if _, err := audit.VerifyFile(f.auditPath); err != nil {
		t.Fatalf("audit log does not verify: %v", err)
	}
	data, err := os.ReadFile(f.auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	return string(data)
}

// approvedCode parks a request, approves it and collects the code.
func (f *fixture) approvedCode(t *testing.T, profile string) string {
	t.Helper()
	p, err := f.store.Park(request())
	if err != nil {
		t.Fatalf("park: %v", err)
	}
	if err := f.store.Decide(context.Background(), p.UserCode, true, profile, admin); err != nil {
		t.Fatalf("decide: %v", err)
	}
	_, code, err := f.store.Collect(p.ID)
	if err != nil || code == "" {
		t.Fatalf("collect: code %q, %v", code, err)
	}
	return code
}

func (f *fixture) tokens(t *testing.T, profile string) oauth.Tokens {
	t.Helper()
	tokens, err := f.store.Exchange(context.Background(), f.approvedCode(t, profile), clientID, redirectURI, resource, verifier)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return tokens
}

func TestApprovedRequestYieldsTokensForTheChosenProfile(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	tokens := f.tokens(t, policy.ProfileRemote)

	identity, err := f.store.Verify(tokens.AccessToken)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if identity.ClientID != clientID || identity.Profile != policy.ProfileRemote {
		t.Fatalf("identity = %+v", identity)
	}
	if tokens.ExpiresIn != oauth.AccessLifetime || tokens.RefreshToken == "" {
		t.Fatalf("tokens = %+v", tokens)
	}
	grants := f.store.Grants()
	if len(grants) != 1 || grants[0].ApprovedBy != admin || grants[0].Resource != resource {
		t.Fatalf("grants = %+v", grants)
	}
	audited := f.auditText(t)
	if !strings.Contains(audited, `"event":"client_approved"`) || !strings.Contains(audited, `"approver":"`+admin+`"`) ||
		!strings.Contains(audited, "profile remote") {
		t.Fatalf("audit log:\n%s", audited)
	}
}

func TestNothingAClientPresentsIsStoredInTheClear(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	code := f.approvedCode(t, policy.ProfileLocal)
	tokens, err := f.store.Exchange(context.Background(), code, clientID, redirectURI, resource, verifier)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	stored, err := os.ReadFile(filepath.Join(f.dir, "grants.json"))
	if err != nil {
		t.Fatalf("read grants: %v", err)
	}
	info, _ := os.Stat(filepath.Join(f.dir, "grants.json"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("grants file mode = %o, want 600", info.Mode().Perm())
	}
	for name, text := range map[string]string{"grants file": string(stored), "audit log": f.auditText(t)} {
		for what, secret := range map[string]string{"code": code, "access token": tokens.AccessToken, "refresh token": tokens.RefreshToken} {
			if strings.Contains(text, secret) {
				t.Errorf("the %s contains the %s", name, what)
			}
		}
	}
}

func TestPendingRequestYieldsNoCodeUntilItIsApproved(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p, err := f.store.Park(request())
	if err != nil {
		t.Fatalf("park: %v", err)
	}

	got, code, err := f.store.Collect(p.ID)
	if err != nil || code != "" || got.Status != oauth.StatusPending {
		t.Fatalf("collect while pending: status %s, code %q, %v", got.Status, code, err)
	}
	if pending := f.store.PendingRequests(); len(pending) != 1 || pending[0].UserCode != p.UserCode {
		t.Fatalf("pending = %+v", pending)
	}
}

func TestCodeIsHandedOutOnce(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p, _ := f.store.Park(request())
	if err := f.store.Decide(context.Background(), p.UserCode, true, policy.ProfileLocal, admin); err != nil {
		t.Fatalf("decide: %v", err)
	}
	if _, code, err := f.store.Collect(p.ID); err != nil || code == "" {
		t.Fatalf("first collect: %q, %v", code, err)
	}

	if _, code, err := f.store.Collect(p.ID); !errors.Is(err, oauth.ErrUnknownRequest) || code != "" {
		t.Fatalf("second collect: %q, %v", code, err)
	}
}

func TestDeniedRequestYieldsNoCode(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p, _ := f.store.Park(request())
	if err := f.store.Decide(context.Background(), p.UserCode, false, "", admin); err != nil {
		t.Fatalf("decide: %v", err)
	}

	got, code, err := f.store.Collect(p.ID)
	if err != nil || code != "" || got.Status != oauth.StatusDenied {
		t.Fatalf("collect: status %s, code %q, %v", got.Status, code, err)
	}
	if !strings.Contains(f.auditText(t), `"event":"client_denied"`) {
		t.Fatal("the denial is not in the audit log")
	}
}

func TestDecisionNeedsAKnownProfileAndAnApprover(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p, _ := f.store.Park(request())
	ctx := context.Background()

	if err := f.store.Decide(ctx, p.UserCode, true, "admin", admin); err == nil {
		t.Error("an unknown profile was accepted")
	}
	if err := f.store.Decide(ctx, p.UserCode, true, policy.ProfileLocal, ""); err == nil {
		t.Error("a decision without an approver was accepted")
	}
	if err := f.store.Decide(ctx, "AAAA-AAAA", true, policy.ProfileLocal, admin); !errors.Is(err, oauth.ErrUnknownRequest) {
		t.Errorf("a wrong user code: %v", err)
	}
	if _, code, _ := f.store.Collect(p.ID); code != "" {
		t.Error("a code was issued without a valid decision")
	}
}

// failingLog refuses every append.
type failingLog struct{}

func (failingLog) Append(context.Context, audit.Entry) (audit.Receipt, error) {
	return audit.Receipt{}, errors.New("disk full")
}

func TestApprovalThatCannotBeRecordedDoesNotTakeEffect(t *testing.T) {
	t.Parallel()
	store, err := oauth.Open(filepath.Join(t.TempDir(), "grants.json"), failingLog{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	p, _ := store.Park(request())

	if err := store.Decide(context.Background(), p.UserCode, true, policy.ProfileLocal, admin); err == nil {
		t.Fatal("an unrecorded approval was accepted")
	}
	if got, code, _ := store.Collect(p.ID); code != "" || got.Status != oauth.StatusPending {
		t.Fatalf("after an unrecorded approval: status %s, code %q", got.Status, code)
	}
}

func TestExchangeRefusesWhatDoesNotMatchTheRequest(t *testing.T) {
	t.Parallel()
	cases := map[string][4]string{
		"another client":       {"https://evil.example/metadata.json", redirectURI, resource, verifier},
		"another redirect URI": {clientID, "http://127.0.0.1:1/other", resource, verifier},
		"another resource":     {clientID, redirectURI, "https://other.example/mcp", verifier},
		"wrong verifier":       {clientID, redirectURI, resource, "another-verifier-that-is-also-long-enough-0123456789"},
		"short verifier":       {clientID, redirectURI, resource, "short"},
		"no verifier":          {clientID, redirectURI, resource, ""},
	}
	for name, c := range cases {
		f := newFixture(t)
		code := f.approvedCode(t, policy.ProfileLocal)
		if _, err := f.store.Exchange(context.Background(), code, c[0], c[1], c[2], c[3]); !errors.Is(err, oauth.ErrInvalidGrant) {
			t.Errorf("%s: %v, want invalid_grant", name, err)
		}
		if len(f.store.Grants()) != 0 {
			t.Errorf("%s: a grant was created", name)
		}
	}
	f := newFixture(t)
	if _, err := f.store.Exchange(context.Background(), "no-such-code", clientID, redirectURI, resource, verifier); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Errorf("unknown code: %v", err)
	}
}

func TestCodePresentedTwiceEndsTheGrantItProduced(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	code := f.approvedCode(t, policy.ProfileLocal)
	tokens, err := f.store.Exchange(context.Background(), code, clientID, redirectURI, resource, verifier)
	if err != nil {
		t.Fatalf("first exchange: %v", err)
	}

	if _, err := f.store.Exchange(context.Background(), code, clientID, redirectURI, resource, verifier); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("second exchange: %v, want invalid_grant", err)
	}

	if _, err := f.store.Verify(tokens.AccessToken); !errors.Is(err, oauth.ErrInvalidToken) {
		t.Fatalf("access token after the replay: %v", err)
	}
	if _, err := f.store.Refresh(context.Background(), tokens.RefreshToken, clientID); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("refresh token after the replay: %v", err)
	}
	if !strings.Contains(f.auditText(t), "authorization code presented twice") {
		t.Fatal("the replay is not in the audit log")
	}
}

func TestCodeAndParkedRequestExpire(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	code := f.approvedCode(t, policy.ProfileLocal)
	f.clock.Advance(oauth.CodeLifetime + time.Second)
	if _, err := f.store.Exchange(context.Background(), code, clientID, redirectURI, resource, verifier); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("exchange of an expired code: %v", err)
	}

	p, _ := f.store.Park(request())
	f.clock.Advance(oauth.PendingLifetime + time.Second)
	if _, _, err := f.store.Collect(p.ID); !errors.Is(err, oauth.ErrUnknownRequest) {
		t.Fatalf("collect of an expired request: %v", err)
	}
	if err := f.store.Decide(context.Background(), p.UserCode, true, policy.ProfileLocal, admin); !errors.Is(err, oauth.ErrUnknownRequest) {
		t.Fatalf("decision on an expired request: %v", err)
	}
}

func TestAccessTokenExpiresAndTheRefreshTokenRenewsIt(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	tokens := f.tokens(t, policy.ProfileLocal)
	f.clock.Advance(oauth.AccessLifetime + time.Second)
	if _, err := f.store.Verify(tokens.AccessToken); !errors.Is(err, oauth.ErrInvalidToken) {
		t.Fatalf("expired access token: %v", err)
	}

	renewed, err := f.store.Refresh(context.Background(), tokens.RefreshToken, clientID)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	if renewed.RefreshToken == tokens.RefreshToken || renewed.AccessToken == tokens.AccessToken {
		t.Fatal("refresh returned a token it had issued before")
	}
	if identity, err := f.store.Verify(renewed.AccessToken); err != nil || identity.Profile != policy.ProfileLocal {
		t.Fatalf("renewed access token: %+v, %v", identity, err)
	}
}

func TestReplacedRefreshTokenPresentedAgainEndsTheGrant(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	tokens := f.tokens(t, policy.ProfileLocal)
	renewed, err := f.store.Refresh(context.Background(), tokens.RefreshToken, clientID)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	if _, err := f.store.Refresh(context.Background(), tokens.RefreshToken, clientID); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("reuse of the replaced refresh token: %v", err)
	}

	if _, err := f.store.Refresh(context.Background(), renewed.RefreshToken, clientID); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("the current refresh token survived the reuse: %v", err)
	}
	if _, err := f.store.Verify(renewed.AccessToken); !errors.Is(err, oauth.ErrInvalidToken) {
		t.Fatalf("the access token survived the reuse: %v", err)
	}
	if len(f.store.Grants()) != 0 {
		t.Fatal("the grant survived the reuse")
	}
}

func TestRefreshTokenIsBoundToItsClient(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	tokens := f.tokens(t, policy.ProfileLocal)

	if _, err := f.store.Refresh(context.Background(), tokens.RefreshToken, "https://evil.example/metadata.json"); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("refresh by another client: %v", err)
	}
	if _, err := f.store.Refresh(context.Background(), tokens.RefreshToken, clientID); err != nil {
		t.Fatalf("the rightful client was locked out: %v", err)
	}
}

func TestRevokedGrantStopsWorkingAtOnce(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	tokens := f.tokens(t, policy.ProfileLocal)
	grant := f.store.Grants()[0]

	if err := f.store.Revoke(context.Background(), grant.ID, admin); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if _, err := f.store.Verify(tokens.AccessToken); !errors.Is(err, oauth.ErrInvalidToken) {
		t.Fatalf("access token after revocation: %v", err)
	}
	if _, err := f.store.Refresh(context.Background(), tokens.RefreshToken, clientID); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("refresh token after revocation: %v", err)
	}
	if !strings.Contains(f.auditText(t), `"event":"grant_revoked"`) {
		t.Fatal("the revocation is not in the audit log")
	}
}

func TestGrantSurvivesARestartAndAnUnusedOneRunsOut(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	tokens := f.tokens(t, policy.ProfileRemote)

	f.open(t)

	if _, err := f.store.Verify(tokens.AccessToken); !errors.Is(err, oauth.ErrInvalidToken) {
		t.Fatalf("access tokens are not meant to survive a restart: %v", err)
	}
	renewed, err := f.store.Refresh(context.Background(), tokens.RefreshToken, clientID)
	if err != nil {
		t.Fatalf("refresh after a restart: %v", err)
	}
	if identity, err := f.store.Verify(renewed.AccessToken); err != nil || identity.Profile != policy.ProfileRemote {
		t.Fatalf("identity after a restart: %+v, %v", identity, err)
	}

	f.clock.Advance(oauth.RefreshIdle + time.Hour)
	if _, err := f.store.Refresh(context.Background(), renewed.RefreshToken, clientID); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("refresh of a grant unused for too long: %v", err)
	}
}

func TestParkedRequestsAreBounded(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	for range oauth.MaxPending {
		if _, err := f.store.Park(request()); err != nil {
			t.Fatalf("park: %v", err)
		}
	}
	if _, err := f.store.Park(request()); !errors.Is(err, oauth.ErrTooManyPending) {
		t.Fatalf("park beyond the bound: %v", err)
	}
}
