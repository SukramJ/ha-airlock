// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/SukramJ/ha-airlock/internal/approval"
	"github.com/SukramJ/ha-airlock/internal/audit"
	"github.com/SukramJ/ha-airlock/internal/oauth"
	"github.com/SukramJ/ha-airlock/internal/provision/provisiontest"
)

const (
	publicURL       = "https://airlock.test"
	testClientID    = "https://client.test/metadata.json"
	testRedirect    = "http://127.0.0.1:41000/callback"
	testVerifier    = "a-code-verifier-that-is-long-enough-for-pkce-0123456789"
	credentialInLog = "hunter2pass"
)

// oneClient is the metadata source of the test: it knows one client and
// never touches the network.
type oneClient struct{}

func (oneClient) Fetch(_ context.Context, id string) (oauth.ClientMetadata, error) {
	if id != testClientID {
		return oauth.ClientMetadata{}, oauth.ErrInvalidClient
	}
	return oauth.ClientMetadata{ClientID: id, ClientName: "Wiring Test Client", RedirectURIs: []string{testRedirect}}, nil
}

// safeBuffer is a log sink the server and the test may use at once.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// running is a server started through run, the way main starts it.
type running struct {
	home    *provisiontest.Home
	dataDir string
	// configDir is the folder the owner's policy file is read from.
	configDir string
	ingress   string
	public    string // empty when the public listener is closed
	log       *safeBuffer
}

// startServer runs "ha-airlock serve" against a stand-in Home Assistant
// and returns once its listeners are up.
func startServer(t *testing.T, optionsJSON string, peers ...netip.Addr) *running {
	t.Helper()
	return startServerIn(t, optionsJSON, nil, peers...)
}

// startServerIn is startServer with a change to the environment the server
// is started in.
func startServerIn(t *testing.T, optionsJSON string, change func(*environment), peers ...netip.Addr) *running {
	t.Helper()
	home := provisiontest.NewHome(t)
	home.CoreResults = map[string]string{"system_log/list": `[{"name":"homeassistant.components.mqtt","level":"ERROR",
		"message":["cannot connect to mqtt://user:` + credentialInLog + `@broker:1883"],"count":2}]`}
	r := &running{home: home, dataDir: t.TempDir(), configDir: t.TempDir(), log: &safeBuffer{}}
	if optionsJSON != "" {
		if err := os.WriteFile(filepath.Join(r.dataDir, "options.json"), []byte(optionsJSON), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if len(peers) == 0 {
		peers = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	}
	listening := make(chan map[string]net.Addr, 1)
	env := environment{
		supervisorURL:   home.Supervisor.URL,
		supervisorToken: provisiontest.SupervisorToken,
		coreHost:        "127.0.0.1",
		dataDir:         r.dataDir,
		configDir:       r.configDir,
		ingressAddr:     "127.0.0.1:0",
		publicAddr:      "127.0.0.1:0",
		supervisorPeers: func(context.Context) ([]netip.Addr, error) { return peers, nil },
		clientMetadata:  oneClient{},
		onListening:     func(addrs map[string]net.Addr) { listening <- addrs },
		now:             time.Now,
		sweepEvery:      sweepEvery,
	}
	if change != nil {
		change(&env)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"serve"}, env, r.log) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("the server did not stop")
		}
	})
	select {
	case addrs := <-listening:
		r.ingress = "http://" + addrs["ingress"].String()
		if a, ok := addrs["public"]; ok {
			r.public = a.String()
		}
	case code := <-done:
		t.Fatalf("the server exited with %d before listening; log:\n%s", code, r.log.String())
	case <-time.After(15 * time.Second):
		t.Fatalf("the server did not start; log:\n%s", r.log.String())
	}
	return r
}

// throughProxy sends requests for the public URL to the server's public
// listener, as the owner's reverse proxy does: over plain HTTP, with the
// public host in the Host header.
type throughProxy struct {
	addr   string
	bearer string
}

func (p throughProxy) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Host = req.URL.Host
	req.URL.Scheme, req.URL.Host = "http", p.addr
	if p.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+p.bearer)
	}
	return http.DefaultTransport.RoundTrip(req)
}

func (r *running) browser() *http.Client {
	return &http.Client{
		Transport:     throughProxy{addr: r.public},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type page struct {
	status   int
	location string
	body     string
	header   http.Header
}

func fetchPage(t *testing.T, client *http.Client, req *http.Request) page {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return page{status: resp.StatusCode, location: resp.Header.Get("Location"), body: string(body), header: resp.Header}
}

func getPage(t *testing.T, client *http.Client, target string) page {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	return fetchPage(t, client, req)
}

// asAdmin sends a request to the ingress listener with the headers the
// Supervisor sets for an administrator.
func (r *running) asAdmin(t *testing.T, method, path string, form url.Values) page {
	t.Helper()
	var body io.Reader = http.NoBody
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(context.Background(), method, r.ingress+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("X-Remote-User-Id", "admin-user-id")
	req.Header.Set("X-Remote-User-Groups", "system-admin")
	return fetchPage(t, http.DefaultClient, req)
}

var (
	userCodeRE  = regexp.MustCompile(`[A-Z2-9]{4}-[A-Z2-9]{4}`)
	formTokenRE = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
)

// authorize plays a client and its owner through the whole OAuth flow and
// returns an access token.
func (r *running) authorize(t *testing.T, profile string) string {
	t.Helper()
	browser := r.browser()
	sum := sha256.Sum256([]byte(testVerifier))
	q := url.Values{
		"response_type": {"code"}, "client_id": {testClientID}, "redirect_uri": {testRedirect}, "state": {"s1"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"resource": {publicURL + oauth.PathMCP},
	}
	started := getPage(t, browser, publicURL+oauth.PathAuthorize+"?"+q.Encode())
	if started.status != http.StatusSeeOther {
		t.Fatalf("authorize: status %d\n%s", started.status, started.body)
	}
	waiting := getPage(t, browser, started.location)
	userCode := userCodeRE.FindString(waiting.body)
	if waiting.status != http.StatusOK || userCode == "" {
		t.Fatalf("waiting page: status %d\n%s", waiting.status, waiting.body)
	}

	consent := r.asAdmin(t, http.MethodGet, "/", nil)
	token := formTokenRE.FindStringSubmatch(consent.body)
	if token == nil || !strings.Contains(consent.body, userCode) {
		t.Fatalf("consent page:\n%s", consent.body)
	}
	decided := r.asAdmin(t, http.MethodPost, "/decide", url.Values{
		"csrf": {token[1]}, "code": {userCode}, "action": {"approve"}, "profile": {profile},
	})
	if decided.status != http.StatusOK {
		t.Fatalf("decide: status %d\n%s", decided.status, decided.body)
	}

	finished := getPage(t, browser, started.location)
	target, err := url.Parse(finished.location)
	if err != nil || finished.status != http.StatusFound || target.Query().Get("code") == "" {
		t.Fatalf("after approval: status %d, location %q", finished.status, finished.location)
	}
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {target.Query().Get("code")}, "client_id": {testClientID},
		"code_verifier": {testVerifier}, "resource": {publicURL + oauth.PathMCP},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, publicURL+oauth.PathToken, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	issued := fetchPage(t, browser, req)
	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(issued.body), &tokens); err != nil || tokens.AccessToken == "" {
		t.Fatalf("token response: %d %s", issued.status, issued.body)
	}
	return tokens.AccessToken
}

func (r *running) callTool(t *testing.T, accessToken, name string) (text string, isError bool) {
	t.Helper()
	return r.callToolWith(t, accessToken, name, nil)
}

func (r *running) callToolWith(t *testing.T, accessToken, name string, args map[string]string) (text string, isError bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "wiring-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             publicURL + oauth.PathMCP,
		HTTPClient:           &http.Client{Transport: throughProxy{addr: r.public, bearer: accessToken}},
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()
	params := &mcp.CallToolParams{Name: name}
	if args != nil {
		params.Arguments = args
	}
	result, err := session.CallTool(ctx, params)
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	content, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content is %T", result.Content[0])
	}
	return content.Text, result.IsError
}

// dismissals counts how often a notification was dismissed in the stand-in
// Home Assistant.
func (r *running) dismissals() int {
	r.home.Mu.Lock()
	defer r.home.Mu.Unlock()
	n := 0
	for _, s := range r.home.Services {
		if s == "persistent_notification.dismiss" {
			n++
		}
	}
	return n
}

func (r *running) auditText(t *testing.T) string {
	t.Helper()
	path := filepath.Join(r.dataDir, "audit.jsonl")
	if _, err := audit.VerifyFile(path); err != nil {
		t.Fatalf("audit log does not verify: %v", err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // test file below t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// The server as main builds it: a client that an administrator approved for
// the local profile calls a tool, and the call passes policy, redaction and
// the audit log.
func TestServedToolCallPassesAuthorizationPolicyRedactionAndAudit(t *testing.T) {
	t.Parallel()
	r := startServer(t, `{"public_url":"`+publicURL+`/"}`)
	accessToken := r.authorize(t, "local")

	text, isError := r.callTool(t, accessToken, "system_log_list")

	if isError || !strings.Contains(text, "homeassistant.components.mqtt") {
		t.Fatalf("tool result: isError = %t, %s", isError, text)
	}
	if strings.Contains(text, credentialInLog) {
		t.Fatalf("a credential reached the client: %s", text)
	}
	audited := r.auditText(t)
	for _, want := range []string{
		`"event":"provisioning"`, `"event":"client_approved"`, `"approver":"admin-user-id"`,
		`"event":"tool_call"`, `"tool":"system_log_list"`, `"client":"` + testClientID + `"`, `"decision":"allow"`,
	} {
		if !strings.Contains(audited, want) {
			t.Errorf("audit log lacks %s:\n%s", want, audited)
		}
	}
	if strings.Contains(audited, credentialInLog) || strings.Contains(audited, accessToken) {
		t.Fatal("the audit log holds a credential")
	}
	if strings.Contains(r.log.String(), accessToken) || strings.Contains(r.log.String(), provisiontest.RefreshToken) {
		t.Fatal("the server log holds a token")
	}
}

// The same server, a client approved for the remote profile: the default
// policy denies it, the tool does not run, and the refusal is recorded.
func TestServedToolCallIsRefusedForAProfileThePolicyDenies(t *testing.T) {
	t.Parallel()
	r := startServer(t, `{"public_url":"`+publicURL+`"}`)
	accessToken := r.authorize(t, "remote")

	text, isError := r.callTool(t, accessToken, "system_log_list")

	if !isError || !strings.Contains(text, "policy") {
		t.Fatalf("tool result: isError = %t, %s", isError, text)
	}
	r.home.Mu.Lock()
	reached := len(r.home.CoreCommands)
	r.home.Mu.Unlock()
	if reached != 0 {
		t.Fatal("Home Assistant was reached although the policy denies the call")
	}
	if audited := r.auditText(t); !strings.Contains(audited, `"decision":"deny"`) {
		t.Fatalf("the refusal is not recorded:\n%s", audited)
	}
}

func TestPublicListenerAnswersUnderThePublicHostOnlyAndRequiresAToken(t *testing.T) {
	t.Parallel()
	r := startServer(t, `{"public_url":"`+publicURL+`"}`)

	direct := getPage(t, http.DefaultClient, "http://"+r.public+oauth.PathServerMetadata)
	if direct.status != http.StatusMisdirectedRequest {
		t.Fatalf("request under the listener's own address: status %d, want 421", direct.status)
	}
	named := getPage(t, r.browser(), publicURL+oauth.PathServerMetadata)
	if named.status != http.StatusOK || !strings.Contains(named.body, `"issuer":"`+publicURL+`"`) {
		t.Fatalf("request under the public host: %d %s", named.status, named.body)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, publicURL+oauth.PathMCP,
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	unauthenticated := fetchPage(t, r.browser(), req)
	if unauthenticated.status != http.StatusUnauthorized ||
		!strings.Contains(unauthenticated.header.Get("WWW-Authenticate"), publicURL+oauth.PathResourceMetadata) {
		t.Fatalf("MCP without a token: %d, challenge %q", unauthenticated.status, unauthenticated.header.Get("WWW-Authenticate"))
	}
	invented, err := http.NewRequestWithContext(context.Background(), http.MethodPost, publicURL+oauth.PathMCP,
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	invented.Header.Set("Content-Type", "application/json")
	invented.Header.Set("Accept", "application/json, text/event-stream")
	invented.Header.Set("Authorization", "Bearer a-token-nobody-issued")
	if got := fetchPage(t, r.browser(), invented); got.status != http.StatusUnauthorized {
		t.Fatalf("MCP with an invented token: status %d, want 401", got.status)
	}
}

func TestConsentPageIsServedToTheSupervisorOnly(t *testing.T) {
	t.Parallel()
	r := startServer(t, `{"public_url":"`+publicURL+`"}`, netip.MustParseAddr("172.30.32.2"))

	// The test connects from 127.0.0.1, which is not the Supervisor here.
	got := r.asAdmin(t, http.MethodGet, "/", nil)

	if got.status != http.StatusForbidden {
		t.Fatalf("consent page for another peer: status %d, want 403", got.status)
	}
}

func TestPublicListenerStaysClosedWithoutAUsablePublicURL(t *testing.T) {
	t.Parallel()
	for name, opts := range map[string]string{
		"no options":     "",
		"empty":          `{"public_url":""}`,
		"plain http":     `{"public_url":"http://airlock.test"}`,
		"with a path":    `{"public_url":"https://airlock.test/airlock"}`,
		"not a URL":      `{"public_url":"airlock.test"}`,
		"with user info": `{"public_url":"https://user@airlock.test"}`,
	} {
		r := startServer(t, opts)
		if r.public != "" {
			t.Errorf("%s: the public listener is open", name)
		}
		if got := r.asAdmin(t, http.MethodGet, "/", nil); got.status != http.StatusOK {
			t.Errorf("%s: consent page status %d, want 200", name, got.status)
		}
		if !strings.Contains(r.log.String(), "no MCP access") {
			t.Errorf("%s: the log does not say why there is no MCP access", name)
		}
	}
}

// The kill switch as the owner operates it, on the server as main builds
// it: once engaged in the sidebar page, an approved client's call is
// refused and recorded, and the switch survives in the data directory.
func TestKillSwitchEngagedInTheSidebarStopsAnApprovedClient(t *testing.T) {
	t.Parallel()
	r := startServer(t, `{"public_url":"`+publicURL+`"}`)
	accessToken := r.authorize(t, "local")
	token := formTokenRE.FindStringSubmatch(r.asAdmin(t, http.MethodGet, "/", nil).body)
	if token == nil {
		t.Fatal("the sidebar page has no form token")
	}

	if got := r.asAdmin(t, http.MethodPost, "/halt", url.Values{"csrf": {token[1]}, "action": {"engage"}}); got.status != http.StatusOK {
		t.Fatalf("engage: status %d", got.status)
	}
	text, isError := r.callTool(t, accessToken, "system_log_list")

	if !isError || !strings.Contains(text, "halted") {
		t.Fatalf("tool result while halted: isError = %t, %s", isError, text)
	}
	r.home.Mu.Lock()
	reached := len(r.home.CoreCommands)
	r.home.Mu.Unlock()
	if reached != 0 {
		t.Fatal("Home Assistant was reached while the kill switch was engaged")
	}
	audited := r.auditText(t)
	if !strings.Contains(audited, `"event":"kill_switch"`) || !strings.Contains(audited, `"decision":"halted"`) {
		t.Fatalf("audit log:\n%s", audited)
	}
	if _, err := os.Stat(filepath.Join(r.dataDir, "halted")); err != nil {
		t.Fatalf("the engaged switch is not stored: %v", err)
	}

	if got := r.asAdmin(t, http.MethodPost, "/halt", url.Values{"csrf": {token[1]}, "action": {"release"}}); got.status != http.StatusOK {
		t.Fatalf("release: status %d", got.status)
	}
	if text, isError := r.callTool(t, accessToken, "system_log_list"); isError {
		t.Fatalf("tool result after release: %s", text)
	}
}

// The audit view on the server as main builds it: the page shows the log
// the gate writes to, and only through the Supervisor.
func TestAuditViewInTheSidebarShowsTheServedToolCall(t *testing.T) {
	t.Parallel()
	r := startServer(t, `{"public_url":"`+publicURL+`"}`)
	accessToken := r.authorize(t, "local")
	if _, isError := r.callTool(t, accessToken, "system_log_list"); isError {
		t.Fatal("the tool call failed")
	}

	got := r.asAdmin(t, http.MethodGet, "/audit", nil)

	if got.status != http.StatusOK {
		t.Fatalf("audit view: status %d", got.status)
	}
	for _, want := range []string{"provisioning", "client_approved", "system_log_list", "allow", "The chain holds"} {
		if !strings.Contains(got.body, want) {
			t.Errorf("the audit view lacks %q:\n%s", want, got.body)
		}
	}
	if strings.Contains(got.body, accessToken) || strings.Contains(got.body, credentialInLog) {
		t.Fatal("the audit view shows a credential")
	}

	other := startServer(t, `{"public_url":"`+publicURL+`"}`, netip.MustParseAddr("172.30.32.2"))
	if got := other.asAdmin(t, http.MethodGet, "/audit", nil); got.status != http.StatusForbidden {
		t.Fatalf("audit view for a peer that is not the Supervisor: status %d, want 403", got.status)
	}
}

var actionIDRE = regexp.MustCompile(`name="id" value="([0-9a-f]+)"`)

// The approval of an action on the server as main builds it: the gate the
// MCP endpoint calls and the page the Supervisor reaches share one store.
// A call the default policy wants approved does not reach Home Assistant
// until an administrator approved it in the sidebar page, and then once.
func TestActionRunsOnlyAfterApprovalInTheSidebar(t *testing.T) {
	t.Parallel()
	r := startServer(t, `{"public_url":"`+publicURL+`"}`)
	r.home.Mu.Lock()
	r.home.CoreResults["config/entity_registry/get"] = `{"labels":["airlock"],"name":"Desk <lamp>","original_name":null}`
	r.home.CoreResults["get_states"] = `[{"entity_id":"light.other","state":"on"},{"entity_id":"light.desk","state":"off"}]`
	r.home.Mu.Unlock()
	accessToken := r.authorize(t, "local")
	args := map[string]string{"entity_id": "light.desk"}
	services := func() []string {
		r.home.Mu.Lock()
		defer r.home.Mu.Unlock()
		var out []string
		for _, s := range r.home.Services {
			if strings.HasPrefix(s, "light.") {
				out = append(out, s)
			}
		}
		return out
	}

	// The start took away whatever notice an earlier run left.
	notices := func() int { return r.dismissals() - 1 }
	// Provisioning announced the new user with a notification of its own.
	r.home.Mu.Lock()
	before := 0
	for _, s := range r.home.Services {
		if s == "persistent_notification.create" {
			before++
		}
	}
	r.home.Mu.Unlock()
	created := func() int {
		r.home.Mu.Lock()
		defer r.home.Mu.Unlock()
		n := 0
		for _, s := range r.home.Services {
			if s == "persistent_notification.create" {
				n++
			}
		}
		return n - before
	}

	text, isError := r.callToolWith(t, accessToken, "light_turn_on", args)
	if isError || !strings.HasPrefix(text, "NOT RUN YET") || len(services()) != 0 {
		t.Fatalf("call before the approval: isError = %t, services %v, %s", isError, services(), text)
	}
	if created() != 1 || notices() != 0 {
		t.Fatalf("the owner was not told that an approval waits: %d notices created, %d dismissed", created(), notices())
	}

	shown := r.asAdmin(t, http.MethodGet, "/", nil).body
	id := actionIDRE.FindStringSubmatch(shown)
	token := formTokenRE.FindStringSubmatch(shown)
	if id == nil || token == nil || !strings.Contains(shown, "Turn on light.desk") || !strings.Contains(shown, "Desk &lt;lamp&gt;") ||
		!strings.Contains(shown, "<dt>State now</dt><dd>off</dd>") {
		t.Fatalf("the sidebar page does not show the waiting action:\n%s", shown)
	}
	if got := r.asAdmin(t, http.MethodPost, "/action", url.Values{"csrf": {token[1]}, "id": {id[1]}, "action": {"approve"}}); got.status != http.StatusOK {
		t.Fatalf("approve: status %d", got.status)
	}

	if created() != 1 || notices() != 1 {
		t.Fatalf("the notice was not taken away after the decision: %d created, %d dismissed", created(), notices())
	}

	text, isError = r.callToolWith(t, accessToken, "light_turn_on", args)
	if isError || !strings.Contains(text, `\"called\":\"light.turn_on\"`) && !strings.Contains(text, `"called":"light.turn_on"`) {
		t.Fatalf("call after the approval: isError = %t, %s", isError, text)
	}
	if got := services(); len(got) != 1 || got[0] != "light.turn_on" {
		t.Fatalf("services called = %v, want one light.turn_on", got)
	}
	if text, _ := r.callToolWith(t, accessToken, "light_turn_on", args); !strings.HasPrefix(text, "NOT RUN YET") || len(services()) != 1 {
		t.Fatalf("the approval was used twice: %s", text)
	}

	audited := r.auditText(t)
	for _, want := range []string{
		`"decision":"approval"`, `"result":"waiting for approval"`, `"event":"action_approved"`, `"approver":"admin-user-id"`,
	} {
		if !strings.Contains(audited, want) {
			t.Errorf("audit log lacks %s:\n%s", want, audited)
		}
	}
}

// An entity without the owner's label is not controlled and not even put
// before the owner, on the server as main builds it.
func TestEntityWithoutTheOwnersLabelIsNotControlled(t *testing.T) {
	t.Parallel()
	r := startServer(t, `{"public_url":"`+publicURL+`"}`)
	r.home.Mu.Lock()
	r.home.CoreResults["config/entity_registry/get"] = `{"labels":["kitchen"],"name":null,"original_name":"Desk"}`
	r.home.Mu.Unlock()
	accessToken := r.authorize(t, "local")

	text, isError := r.callToolWith(t, accessToken, "switch_turn_off", map[string]string{"entity_id": "switch.heating"})

	if !isError || !strings.Contains(text, "not released") {
		t.Fatalf("isError = %t, %s", isError, text)
	}
	if shown := r.asAdmin(t, http.MethodGet, "/", nil).body; !strings.Contains(shown, "No action is waiting") {
		t.Fatalf("the refused call waits for approval:\n%s", shown)
	}
	r.home.Mu.Lock()
	defer r.home.Mu.Unlock()
	for _, s := range r.home.Services {
		if strings.HasPrefix(s, "switch.") {
			t.Fatalf("a service was called: %v", r.home.Services)
		}
	}
	if !strings.Contains(r.auditText(t), `"decision":"not_released"`) {
		t.Fatal("the refusal is not recorded")
	}
}

// A request nobody decides on expires on the server as main builds it,
// without a further call from anyone: the expiry is recorded and the notice
// in Home Assistant is taken away.
func TestWaitingActionExpiresOnTheRunningServerWithoutAFurtherCall(t *testing.T) {
	t.Parallel()
	var ahead atomic.Int64 // nanoseconds the server's clock is ahead
	r := startServerIn(t, `{"public_url":"`+publicURL+`"}`, func(env *environment) {
		env.now = func() time.Time { return time.Now().Add(time.Duration(ahead.Load())) }
		env.sweepEvery = 10 * time.Millisecond
	})
	r.home.Mu.Lock()
	r.home.CoreResults["config/entity_registry/get"] = `{"labels":["airlock"],"name":"Desk","original_name":null}`
	r.home.Mu.Unlock()
	accessToken := r.authorize(t, "local")
	// One dismissal is the start's own.
	dismissed := func() bool { return r.dismissals() > 1 }

	if text, _ := r.callToolWith(t, accessToken, "light_turn_on", map[string]string{"entity_id": "light.desk"}); !strings.HasPrefix(text, "NOT RUN YET") {
		t.Fatalf("the call was not parked: %s", text)
	}
	// Several sweeps pass while the request is still within its time.
	time.Sleep(100 * time.Millisecond)
	if dismissed() || strings.Contains(r.auditText(t), "action_expired") {
		t.Fatal("the request expired before its time")
	}

	ahead.Store(int64(approval.WaitFor + time.Second))

	deadline := time.Now().Add(10 * time.Second)
	for !dismissed() || !strings.Contains(r.auditText(t), `"event":"action_expired"`) {
		if time.Now().After(deadline) {
			t.Fatalf("the expiry was not noticed: notice dismissed = %t, audit log:\n%s", dismissed(), r.auditText(t))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A helper is changed through the server as main builds it: the policy
// file opens the kind, the call waits with its difference on the sidebar
// page, and after the approval the change is in the journal and was sent
// to Home Assistant.
func TestHelperIsChangedOnlyAfterApprovalAndIsJournalled(t *testing.T) {
	t.Parallel()
	r := startServerIn(t, `{"public_url":"`+publicURL+`"}`, func(env *environment) {
		policyFile := `{"version":1,"profiles":{"local":{"R0":"allow","R2":"approval"}},"configuration":{"local":{"helper":{"change":"approval"}}}}`
		if err := os.WriteFile(filepath.Join(env.configDir, "policy.json"), []byte(policyFile), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	r.home.Mu.Lock()
	r.home.CoreResults["config/entity_registry/get"] = `{"labels":["airlock"],"platform":"input_boolean","unique_id":"guest_mode","name":"Guests <here>","original_name":null}`
	r.home.CoreResults["input_boolean/list"] = `[{"id":"guest_mode","name":"Guest mode","icon":"mdi:account"}]`
	r.home.CoreResults["input_boolean/update"] = `null`
	r.home.CoreResults["get_states"] = `[{"entity_id":"input_boolean.guests","state":"off"}]`
	r.home.Mu.Unlock()
	accessToken := r.authorize(t, "local")
	args := map[string]string{"entity_id": "input_boolean.guests", "name": "Visitors"}
	updates := func() int {
		r.home.Mu.Lock()
		defer r.home.Mu.Unlock()
		n := 0
		for _, c := range r.home.CoreCommands {
			if c == "input_boolean/update" {
				n++
			}
		}
		return n
	}

	text, isError := r.callToolWith(t, accessToken, "input_boolean_update", args)
	if isError || !strings.HasPrefix(text, "NOT RUN YET") || updates() != 0 {
		t.Fatalf("call before the approval: isError = %t, %d updates, %s", isError, updates(), text)
	}
	shown := r.asAdmin(t, http.MethodGet, "/", nil).body
	for _, want := range []string{
		"Change the toggle helper input_boolean.guests",
		"<dt>Changes</dt><dd>helper input_boolean.guests — Guests &lt;here&gt;</dd>",
		`<tr class="changed"><td>icon</td><td><code>&#34;mdi:account&#34;</code></td><td></td></tr>`,
		`<tr class="changed"><td>name</td><td><code>&#34;Guest mode&#34;</code></td><td><code>&#34;Visitors&#34;</code></td></tr>`,
	} {
		if !strings.Contains(shown, want) {
			t.Fatalf("the sidebar page lacks %q:\n%s", want, shown)
		}
	}
	id, token := actionIDRE.FindStringSubmatch(shown), formTokenRE.FindStringSubmatch(shown)
	if id == nil || token == nil {
		t.Fatalf("the sidebar page has no form for the change:\n%s", shown)
	}
	if got := r.asAdmin(t, http.MethodPost, "/action", url.Values{"csrf": {token[1]}, "id": {id[1]}, "action": {"approve"}}); got.status != http.StatusOK {
		t.Fatalf("approve: status %d", got.status)
	}

	text, isError = r.callToolWith(t, accessToken, "input_boolean_update", args)
	if isError || !strings.Contains(text, "input_boolean.guests") || !strings.Contains(text, "changed") || updates() != 1 {
		t.Fatalf("call after the approval: isError = %t, %d updates, %s", isError, updates(), text)
	}
	journal, err := os.ReadFile(filepath.Join(r.dataDir, "changes.json")) //nolint:gosec // test file below t.TempDir
	if err != nil {
		t.Fatalf("the journal of changes: %v", err)
	}
	for _, want := range []string{`"object":"input_boolean.guests"`, `"before":{"icon":"mdi:account","name":"Guest mode"}`, `"after":{"name":"Visitors"}`} {
		if !strings.Contains(string(journal), want) {
			t.Errorf("the journal lacks %s:\n%s", want, journal)
		}
	}
	if audited := r.auditText(t); !strings.Contains(audited, "; change ") || !strings.Contains(audited, `"tool":"input_boolean_update"`) {
		t.Errorf("the audit log does not name the change:\n%s", audited)
	}

	// The change is on the sidebar page, and an administrator takes it
	// back there: Home Assistant, which now holds the new configuration,
	// is sent the old one.
	r.home.Mu.Lock()
	r.home.CoreResults["input_boolean/list"] = `[{"id":"guest_mode","name":"Visitors"}]`
	r.home.Mu.Unlock()
	shown = r.asAdmin(t, http.MethodGet, "/", nil).body
	undoID := undoIDRE.FindStringSubmatch(shown)
	token = formTokenRE.FindStringSubmatch(shown)
	if undoID == nil || token == nil || !strings.Contains(shown, "<strong>Changed helper input_boolean.guests</strong>") {
		t.Fatalf("the sidebar page does not list the change:\n%s", shown)
	}
	got := r.asAdmin(t, http.MethodPost, "/undo", url.Values{"csrf": {token[1]}, "id": {undoID[1]}})
	if got.status != http.StatusOK || !strings.Contains(got.body, "Undone.") || updates() != 2 {
		t.Fatalf("undo: status %d, %d updates:\n%s", got.status, updates(), got.body)
	}
	if audited := r.auditText(t); !strings.Contains(audited, `"event":"change_undone"`) || !strings.Contains(audited, `"approver":"admin-user-id"`) {
		t.Errorf("the audit log does not record the undo:\n%s", audited)
	}
	if strings.Contains(r.asAdmin(t, http.MethodGet, "/", nil).body, `action="undo"`) {
		t.Error("a change that was undone can be undone again")
	}
}

var undoIDRE = regexp.MustCompile(`action="undo"><input type="hidden" name="csrf" value="[^"]+"><input type="hidden" name="id" value="([0-9a-f]+)"`)

// A policy file where earlier versions read it is neither read nor passed
// over: it may be stricter than the default, so the server does not start.
func TestServerDoesNotStartWithAPolicyFileLeftInTheDataDirectory(t *testing.T) {
	t.Parallel()
	home := provisiontest.NewHome(t)
	dataDir, configDir := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "policy.json"), []byte(`{"version":1,"profiles":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := environment{
		supervisorURL: home.Supervisor.URL, supervisorToken: provisiontest.SupervisorToken, coreHost: "127.0.0.1",
		dataDir: dataDir, configDir: configDir, ingressAddr: "127.0.0.1:0", publicAddr: "127.0.0.1:0",
		supervisorPeers: func(context.Context) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		clientMetadata: oneClient{}, now: time.Now, sweepEvery: sweepEvery,
	}
	var log safeBuffer
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	code := run(ctx, []string{"serve"}, env, &log)

	if code != exitFailed || !strings.Contains(log.String(), "policy.json in the data directory is no longer read") {
		t.Fatalf("exit code %d, log:\n%s", code, log.String())
	}
}

// No waiting request outlives the server, so a notice that an earlier run
// left in Home Assistant is taken away when the server starts.
func TestStartTakesAwayANoticeLeftByAnEarlierRun(t *testing.T) {
	t.Parallel()
	r := startServer(t, "")

	if got := r.dismissals(); got != 1 {
		t.Fatalf("notices dismissed at the start = %d, want 1", got)
	}
}

// noticeCore records the service calls of the approval notice.
type noticeCore struct {
	calls []string
	fail  bool
}

func (c *noticeCore) Call(_ context.Context, command string, params, _ any) error {
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	c.calls = append(c.calls, command+" "+string(raw))
	if c.fail {
		return errors.New("core is away")
	}
	return nil
}

// The notice says that something waits and nothing else: no action, no
// entity, no application. It is one notification, replaced and dismissed
// by its id.
func TestApprovalNoticeNamesNothingAndIsOneNotification(t *testing.T) {
	t.Parallel()
	core := &noticeCore{}
	var log safeBuffer
	notify := approvalNotice(core, slog.New(slog.NewTextHandler(&log, nil)))

	notify(context.Background(), true)
	notify(context.Background(), false)

	want := []string{
		`call_service {"domain":"persistent_notification","service":"create","service_data":{"message":"An action is waiting for your approval. Open ha-airlock in Home Assistant to see it.","notification_id":"ha_airlock_approval","title":"ha-airlock"}}`,
		`call_service {"domain":"persistent_notification","service":"dismiss","service_data":{"notification_id":"ha_airlock_approval"}}`,
	}
	if len(core.calls) != 2 || core.calls[0] != want[0] || core.calls[1] != want[1] {
		t.Fatalf("calls =\n%s\nwant\n%s", strings.Join(core.calls, "\n"), strings.Join(want, "\n"))
	}

	// A notice that cannot be sent is logged; it stops nothing.
	core.fail = true
	notify(context.Background(), true)
	if !strings.Contains(log.String(), "approval notice could not be updated") {
		t.Fatalf("log = %s", log.String())
	}
}
