// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

// Package oauth is ha-airlock's authorization server (ADR 0004): it parks
// authorization requests until an administrator decides on them, issues
// authorization codes, and issues and verifies access and refresh tokens.
//
// This file holds the state and its rules, without HTTP. Everything a
// client may present later — code, access token, refresh token — is random
// and kept only as a SHA-256 hash.
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/SukramJ/ha-airlock/internal/audit"
	"github.com/SukramJ/ha-airlock/internal/policy"
)

// Lifetimes. An authorization code is redeemed within seconds by a working
// client; a parked request waits for a person.
const (
	pendingLifetime = 10 * time.Minute
	codeLifetime    = time.Minute
	accessLifetime  = 15 * time.Minute
	// refreshIdle is how long a grant survives without being used.
	refreshIdle = 30 * 24 * time.Hour
	// maxPending bounds the parked requests, so that the authorization
	// endpoint cannot be used to fill memory.
	maxPending = 50
)

// Errors of the token endpoint, named after the OAuth error codes they
// become.
var (
	// ErrInvalidGrant covers a code or refresh token that is unknown, used,
	// expired, revoked, or presented by another client.
	ErrInvalidGrant = errors.New("invalid_grant")
	// ErrUnknownRequest reports a parked request that does not exist or has
	// expired.
	ErrUnknownRequest = errors.New("unknown or expired authorization request")
	// ErrTooManyPending reports that no further request can be parked.
	ErrTooManyPending = errors.New("too many authorization requests are waiting")
	// ErrInvalidToken reports an access token that is not valid.
	ErrInvalidToken = errors.New("invalid access token")
)

// Appender is the audit log as the authorization server uses it.
type Appender interface {
	Append(ctx context.Context, entry audit.Entry) (audit.Receipt, error)
}

// Request is an authorization request as validated by the endpoint.
type Request struct {
	ClientID    string
	ClientName  string
	RedirectURI string
	State       string
	// Challenge is the PKCE code challenge, method S256.
	Challenge string
	Resource  string
}

// Status is where a parked request stands.
type Status string

// The states of a parked request.
const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
)

// Pending is a parked authorization request as the consent screen shows it.
type Pending struct {
	// ID identifies the request to the browser that started it. It is a
	// secret of that browser: whoever holds it receives the code.
	ID string
	// UserCode is shown in the waiting browser and on the consent screen,
	// for the administrator to compare.
	UserCode  string
	Request   Request
	CreatedAt time.Time
	Status    Status
	profile   string
	approver  string
}

// Grant is one approved client. It is what the administrator sees and
// revokes.
type Grant struct {
	ID         string    `json:"id"`
	ClientID   string    `json:"client_id"`
	ClientName string    `json:"client_name"`
	Profile    string    `json:"profile"`
	Resource   string    `json:"resource"`
	ApprovedBy string    `json:"approved_by"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsed   time.Time `json:"last_used"`
	// RefreshHash is the hash of the refresh token in force, PreviousHash
	// the one it replaced: presenting the previous one again means the
	// token was copied, and ends the grant.
	RefreshHash  string `json:"refresh_hash"`
	PreviousHash string `json:"previous_hash,omitempty"`
}

// Tokens is what the token endpoint returns.
type Tokens struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    time.Duration
}

// Identity is what a valid access token stands for.
type Identity struct {
	GrantID    string
	ClientID   string
	Profile    string
	Expiration time.Time
}

type code struct {
	request   Request
	profile   string
	approver  string
	expires   time.Time
	used      bool
	grantedID string
}

type access struct {
	grantID string
	expires time.Time
}

// Store is the authorization server's state. It is safe for concurrent use.
type Store struct {
	mu      sync.Mutex
	path    string
	audit   Appender
	now     func() time.Time
	grants  map[string]*Grant
	pending map[string]*Pending
	codes   map[string]*code
	access  map[string]*access
}

// Open loads the grants stored at path, or starts empty if the file does
// not exist. Parked requests, codes and access tokens are not stored: they
// are short-lived, and a client whose access token is gone uses its refresh
// token.
func Open(path string, log Appender) (*Store, error) {
	s := &Store{
		path: path, audit: log, now: time.Now,
		grants: map[string]*Grant{}, pending: map[string]*Pending{},
		codes: map[string]*code{}, access: map[string]*access{},
	}
	data, err := os.ReadFile(path) //nolint:gosec // the path is the operator's configuration, not client input
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("oauth: read grants: %w", err)
	}
	var grants []*Grant
	if err := json.Unmarshal(data, &grants); err != nil {
		return nil, fmt.Errorf("oauth: read grants: %w", err)
	}
	for _, g := range grants {
		s.grants[g.ID] = g
	}
	return s, nil
}

// Park stores a validated authorization request until an administrator
// decides on it.
func (s *Store) Park(req *Request) (Pending, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	if len(s.pending) >= maxPending {
		return Pending{}, ErrTooManyPending
	}
	id, err := randomToken()
	if err != nil {
		return Pending{}, err
	}
	userCode, err := randomUserCode()
	if err != nil {
		return Pending{}, err
	}
	p := &Pending{ID: id, UserCode: userCode, Request: *req, CreatedAt: s.now(), Status: StatusPending}
	s.pending[id] = p
	return *p, nil
}

// PendingRequests returns the parked requests that still wait for a
// decision, oldest first.
func (s *Store) PendingRequests() []Pending {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	out := make([]Pending, 0, len(s.pending))
	for _, p := range s.pending {
		if p.Status == StatusPending {
			out = append(out, *p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// Decide records an administrator's decision on the request with the given
// user code. approver is the Home Assistant user the Supervisor named.
func (s *Store) Decide(ctx context.Context, userCode string, approve bool, profile, approver string) error {
	if approve && profile != policy.ProfileLocal && profile != policy.ProfileRemote {
		return fmt.Errorf("oauth: unknown profile %q", profile)
	}
	if approver == "" {
		return errors.New("oauth: a decision needs the user who took it")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	var p *Pending
	for _, candidate := range s.pending {
		if candidate.Status == StatusPending && subtle.ConstantTimeCompare([]byte(candidate.UserCode), []byte(userCode)) == 1 {
			p = candidate
		}
	}
	if p == nil {
		return ErrUnknownRequest
	}

	entry := audit.Entry{Client: p.Request.ClientID, Approver: approver}
	if approve {
		entry.Event, entry.Decision = "client_approved", "profile "+profile
	} else {
		entry.Event, entry.Decision = "client_denied", "denied"
	}
	entry.Result = "redirect host " + hostOf(p.Request.RedirectURI)
	// The decision takes effect only once it is on record.
	if _, err := s.audit.Append(ctx, entry); err != nil {
		return fmt.Errorf("oauth: record decision: %w", err)
	}
	if approve {
		p.Status, p.profile, p.approver = StatusApproved, profile, approver
	} else {
		p.Status = StatusDenied
	}
	return nil
}

// Collect is called for the browser that waits on a parked request. While
// the request is pending it returns it unchanged. Once it is decided the
// request is consumed: for an approval a fresh authorization code is
// returned, exactly once.
func (s *Store) Collect(id string) (p Pending, authorizationCode string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	found, ok := s.pending[id]
	if !ok {
		return Pending{}, "", ErrUnknownRequest
	}
	if found.Status == StatusPending {
		return *found, "", nil
	}
	delete(s.pending, id)
	if found.Status == StatusDenied {
		return *found, "", nil
	}
	value, err := randomToken()
	if err != nil {
		return Pending{}, "", err
	}
	s.codes[hash(value)] = &code{
		request: found.Request, profile: found.profile, approver: found.approver,
		expires: s.now().Add(codeLifetime),
	}
	return *found, value, nil
}

// Exchange redeems an authorization code. The client must present the same
// client id and redirect URI as in the authorization request, the resource
// if it names one, and the PKCE verifier matching the challenge.
func (s *Store) Exchange(ctx context.Context, authorizationCode, clientID, redirectURI, resource, verifier string) (Tokens, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	c, ok := s.codes[hash(authorizationCode)]
	if !ok {
		return Tokens{}, ErrInvalidGrant
	}
	if c.used {
		// A code presented twice was intercepted or replayed: what it
		// produced is withdrawn.
		if c.grantedID != "" {
			s.revokeLocked(ctx, c.grantedID, "authorization code presented twice")
		}
		return Tokens{}, ErrInvalidGrant
	}
	if c.request.ClientID != clientID ||
		(redirectURI != "" && redirectURI != c.request.RedirectURI) ||
		(resource != "" && resource != c.request.Resource) ||
		!verifierMatches(verifier, c.request.Challenge) {
		return Tokens{}, ErrInvalidGrant
	}
	c.used = true

	id, err := randomToken()
	if err != nil {
		return Tokens{}, err
	}
	now := s.now()
	g := &Grant{
		ID: id[:16], ClientID: c.request.ClientID, ClientName: c.request.ClientName,
		Profile: c.profile, Resource: c.request.Resource, ApprovedBy: c.approver,
		CreatedAt: now, LastUsed: now,
	}
	tokens, err := s.issueLocked(g)
	if err != nil {
		return Tokens{}, err
	}
	s.grants[g.ID] = g
	c.grantedID = g.ID
	if err := s.saveLocked(); err != nil {
		delete(s.grants, g.ID)
		return Tokens{}, err
	}
	return tokens, nil
}

// Refresh exchanges a refresh token for new tokens. The refresh token is
// replaced on every use; one that was already replaced ends the grant.
func (s *Store) Refresh(ctx context.Context, refreshToken, clientID string) (Tokens, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	h := hash(refreshToken)
	for _, g := range s.grants {
		if g.PreviousHash != "" && g.PreviousHash == h {
			s.revokeLocked(ctx, g.ID, "replaced refresh token presented again")
			return Tokens{}, ErrInvalidGrant
		}
		if g.RefreshHash != h {
			continue
		}
		if g.ClientID != clientID {
			return Tokens{}, ErrInvalidGrant
		}
		previous := *g
		g.PreviousHash = g.RefreshHash
		g.LastUsed = s.now()
		tokens, err := s.issueLocked(g)
		if err != nil {
			*g = previous
			return Tokens{}, err
		}
		if err := s.saveLocked(); err != nil {
			*g = previous
			return Tokens{}, err
		}
		return tokens, nil
	}
	return Tokens{}, ErrInvalidGrant
}

// Verify returns what an access token stands for.
func (s *Store) Verify(accessToken string) (Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	a, ok := s.access[hash(accessToken)]
	if !ok {
		return Identity{}, ErrInvalidToken
	}
	g, ok := s.grants[a.grantID]
	if !ok {
		return Identity{}, ErrInvalidToken
	}
	return Identity{GrantID: g.ID, ClientID: g.ClientID, Profile: g.Profile, Expiration: a.expires}, nil
}

// Grants returns the approved clients, newest first.
func (s *Store) Grants() []Grant {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	out := make([]Grant, 0, len(s.grants))
	for _, g := range s.grants {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Revoke ends a grant: its access and refresh tokens stop working at once.
func (s *Store) Revoke(ctx context.Context, grantID, revokedBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.grants[grantID]; !ok {
		return errors.New("oauth: no such grant")
	}
	s.revokeLocked(ctx, grantID, "revoked by "+revokedBy)
	return s.saveLocked()
}

// revokeLocked removes a grant and everything issued under it.
func (s *Store) revokeLocked(ctx context.Context, grantID, reason string) {
	g, ok := s.grants[grantID]
	if !ok {
		return
	}
	delete(s.grants, grantID)
	for h, a := range s.access {
		if a.grantID == grantID {
			delete(s.access, h)
		}
	}
	// The grant is gone whether or not this can be written; a failure to
	// record must not keep a compromised grant alive.
	_, _ = s.audit.Append(context.WithoutCancel(ctx), audit.Entry{
		Event: "grant_revoked", Client: g.ClientID, Result: reason,
	})
	_ = s.saveLocked()
}

// issueLocked gives a grant a new access token and a new refresh token.
func (s *Store) issueLocked(g *Grant) (Tokens, error) {
	accessToken, err := randomToken()
	if err != nil {
		return Tokens{}, err
	}
	refreshToken, err := randomToken()
	if err != nil {
		return Tokens{}, err
	}
	s.access[hash(accessToken)] = &access{grantID: g.ID, expires: s.now().Add(accessLifetime)}
	g.RefreshHash = hash(refreshToken)
	return Tokens{AccessToken: accessToken, RefreshToken: refreshToken, ExpiresIn: accessLifetime}, nil
}

// expire drops what has run out. Callers hold the lock.
func (s *Store) expire() {
	now := s.now()
	for id, p := range s.pending {
		if now.Sub(p.CreatedAt) > pendingLifetime {
			delete(s.pending, id)
		}
	}
	for h, c := range s.codes {
		// A used code is kept until it expires, so that a second
		// presentation is recognised as one.
		if now.After(c.expires) {
			delete(s.codes, h)
		}
	}
	for h, a := range s.access {
		if now.After(a.expires) {
			delete(s.access, h)
		}
	}
	changed := false
	for id, g := range s.grants {
		if now.Sub(g.LastUsed) > refreshIdle {
			delete(s.grants, id)
			changed = true
		}
	}
	if changed {
		_ = s.saveLocked()
	}
}

// saveLocked writes the grants so that the file is complete or unchanged.
func (s *Store) saveLocked() error {
	grants := make([]*Grant, 0, len(s.grants))
	for _, g := range s.grants {
		grants = append(grants, g)
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].ID < grants[j].ID })
	data, err := json.Marshal(grants)
	if err != nil {
		return fmt.Errorf("oauth: store grants: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".grants-*")
	if err != nil {
		return fmt.Errorf("oauth: store grants: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("oauth: store grants: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("oauth: store grants: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("oauth: store grants: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("oauth: store grants: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("oauth: store grants: %w", err)
	}
	return nil
}

// verifierMatches checks a PKCE verifier against an S256 challenge.
func verifierMatches(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// randomToken returns 32 random bytes in URL-safe base64.
func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("oauth: random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// userCodeAlphabet leaves out characters that are easily confused.
const userCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// randomUserCode returns a code of the form XXXX-XXXX for a person to
// compare.
func randomUserCode() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("oauth: random: %w", err)
	}
	out := make([]byte, 0, 9)
	for i, b := range raw {
		if i == 4 {
			out = append(out, '-')
		}
		// 256 is a multiple of the alphabet's 32 characters: no bias.
		out = append(out, userCodeAlphabet[int(b)%len(userCodeAlphabet)])
	}
	return string(out), nil
}

func hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// hostOf returns the host of a URL for display, or the whole value if it
// is not a URL.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}
