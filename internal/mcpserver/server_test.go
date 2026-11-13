// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package mcpserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/SukramJ/ha-airlock/internal/approval"
	"github.com/SukramJ/ha-airlock/internal/audit"
	"github.com/SukramJ/ha-airlock/internal/catalog"
	"github.com/SukramJ/ha-airlock/internal/gate"
	"github.com/SukramJ/ha-airlock/internal/mcpserver"
	"github.com/SukramJ/ha-airlock/internal/policy"
)

const (
	localToken  = "token-of-the-local-client"
	remoteToken = "token-of-the-remote-client"
	metadataURL = "https://airlock.example/.well-known/oauth-protected-resource"
)

// fakeCore answers system_log/list with one entry that carries a credential.
type fakeCore struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeCore) Call(_ context.Context, command string, _, out any) error {
	f.mu.Lock()
	f.calls = append(f.calls, command)
	f.mu.Unlock()
	switch command {
	case "config/entity_registry/get":
		return json.Unmarshal([]byte(`{"labels":["airlock"],"name":null,"original_name":"Lamp"}`), out)
	case "call_service":
		return json.Unmarshal([]byte(`{"context":{"id":"01J"}}`), out)
	}
	return json.Unmarshal([]byte(`[{"name":"homeassistant.components.mqtt","level":"ERROR",
		"message":["cannot connect to mqtt://user:hunter2pass@broker:1883"],"count":2}]`), out)
}

func (f *fakeCore) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// countOf returns how often one command was sent.
func (f *fakeCore) countOf(command string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == command {
			n++
		}
	}
	return n
}

// verify accepts the two test tokens.
func verify(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	switch token {
	case localToken:
		return mcpserver.TokenInfo("client-local", policy.ProfileLocal, time.Now().Add(time.Hour)), nil
	case remoteToken:
		return mcpserver.TokenInfo("client-remote", policy.ProfileRemote, time.Now().Add(time.Hour)), nil
	default:
		return nil, auth.ErrInvalidToken
	}
}

type fixture struct {
	url       string
	core      *fakeCore
	auditPath string
	approvals *approval.Store
}

// newFixture builds the server from the real catalogue and serves it over
// HTTP, the way the composition root does.
func newFixture(t *testing.T) fixture {
	t.Helper()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(auditPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	core := &fakeCore{}
	approvals := approval.New(log, nil, time.Now)
	g := gate.New(gate.Config{
		Policy: policy.Default(), Audit: log, Core: core, Tools: catalog.All(), Timeout: 5 * time.Second, Approvals: approvals,
	})
	server := mcpserver.New(g, catalog.All(), "test")
	// The handler needs the host it is served under, which exists only once
	// the test server listens.
	var handler http.Handler
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(httpServer.Close)
	handler = mcpserver.Handler(server, verify, metadataURL, strings.TrimPrefix(httpServer.URL, "http://"))
	return fixture{url: httpServer.URL, core: core, auditPath: auditPath, approvals: approvals}
}

// bearer adds an access token to every request.
type bearer struct{ token string }

func (b bearer) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(req)
}

func connect(t *testing.T, f fixture, token string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             f.url,
		HTTPClient:           &http.Client{Transport: bearer{token: token}},
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func call(t *testing.T, session *mcp.ClientSession, name string, args map[string]any) (text string, isError bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	if len(result.Content) != 1 {
		t.Fatalf("call %s: %d content parts, want 1", name, len(result.Content))
	}
	content, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("call %s: content is %T", name, result.Content[0])
	}
	return content.Text, result.IsError
}

func (f fixture) auditText(t *testing.T) string {
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

func TestServerOffersExactlyTheCatalogue(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	session := connect(t, f, localToken)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	listed, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}

	want := catalog.All()
	if len(listed.Tools) != len(want) {
		t.Fatalf("%d tools listed, catalogue has %d", len(listed.Tools), len(want))
	}
	for _, tool := range want {
		found := false
		for _, got := range listed.Tools {
			if got.Name == tool.Name {
				found = true
				if got.Annotations == nil || got.Annotations.ReadOnlyHint != (tool.Tier == catalog.R0) {
					t.Errorf("tool %s: read-only hint does not follow its tier", tool.Name)
				}
			}
		}
		if !found {
			t.Errorf("catalogue tool %s is not offered", tool.Name)
		}
	}
}

func TestRequestWithoutAValidTokenIsRefusedBeforeTheServer(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	for name, header := range map[string]string{"no token": "", "wrong token": "Bearer nonsense"} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, f.url,
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"system_log_list"}}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, resp.StatusCode)
		}
		if challenge := resp.Header.Get("WWW-Authenticate"); !strings.Contains(challenge, metadataURL) {
			t.Errorf("%s: challenge %q does not name the resource metadata", name, challenge)
		}
	}
	if f.core.count() != 0 {
		t.Fatal("Home Assistant was reached without a valid token")
	}
}

func TestToolCallOfAnAllowedClientPassesTheWholeChain(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	session := connect(t, f, localToken)

	text, isError := call(t, session, "system_log_list", map[string]any{"limit": 10})

	if isError {
		t.Fatalf("call failed: %s", text)
	}
	var wrapped struct {
		Notice string `json:"notice"`
	}
	if err := json.Unmarshal([]byte(text), &wrapped); err != nil {
		t.Fatalf("result is not JSON: %v", err)
	}
	if wrapped.Notice != gate.Notice || !strings.Contains(text, "homeassistant.components.mqtt") {
		t.Fatalf("result = %s", text)
	}
	if strings.Contains(text, "hunter2pass") {
		t.Fatalf("a credential reached the client: %s", text)
	}
	audited := f.auditText(t)
	if !strings.Contains(audited, `"client":"client-local"`) || !strings.Contains(audited, `"decision":"allow"`) ||
		!strings.Contains(audited, `"tool":"system_log_list"`) {
		t.Fatalf("audit log:\n%s", audited)
	}
	if strings.Contains(audited, "hunter2pass") {
		t.Fatalf("a credential reached the audit log:\n%s", audited)
	}
}

func TestToolCallOfAClientThePolicyDeniesRunsNothing(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	session := connect(t, f, remoteToken)

	text, isError := call(t, session, "system_log_list", nil)

	if !isError || !strings.Contains(text, "policy") {
		t.Fatalf("result = %q, isError = %t", text, isError)
	}
	if f.core.count() != 0 {
		t.Fatal("Home Assistant was reached although the policy denies the call")
	}
	audited := f.auditText(t)
	if !strings.Contains(audited, `"client":"client-remote"`) || !strings.Contains(audited, `"decision":"deny"`) {
		t.Fatalf("audit log:\n%s", audited)
	}
}

func TestCallOfAnUndeclaredToolIsRefusedAndRecorded(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	session := connect(t, f, localToken)

	text, isError := call(t, session, "call_any_service", map[string]any{"domain": "lock", "service": "unlock"})

	if !isError || !strings.Contains(text, "no such tool") {
		t.Fatalf("result = %q, isError = %t", text, isError)
	}
	if f.core.count() != 0 {
		t.Fatal("Home Assistant was reached by an undeclared tool")
	}
	audited := f.auditText(t)
	if !strings.Contains(audited, `"tool":"call_any_service"`) || !strings.Contains(audited, `"decision":"unknown_tool"`) {
		t.Fatalf("audit log:\n%s", audited)
	}
}

func TestRequestUnderAnotherHostNameIsRefused(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, f.url,
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"system_log_list"}}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "attacker.example"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+localToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status %d, want 421", resp.StatusCode)
	}
	if f.core.count() != 0 {
		t.Fatal("Home Assistant was reached under a foreign host name")
	}
}

// A call the policy wants approved, over MCP: the client is told in plain
// words that nothing ran, cannot approve anything itself, and gets the
// result once an administrator approved.
func TestCallWaitingForApprovalIsReportedAsNotRunAndRunsAfterTheApproval(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	session := connect(t, f, localToken)
	args := map[string]any{"entity_id": "light.lamp"}

	text, isError := call(t, session, "light_turn_on", args)
	if isError || !strings.HasPrefix(text, "NOT RUN YET") || f.core.countOf("call_service") != 0 {
		t.Fatalf("waiting call: isError = %t, %d service calls, %s", isError, f.core.countOf("call_service"), text)
	}
	pending := f.approvals.Pending()
	if len(pending) != 1 || pending[0].Client != "client-local" || strings.Contains(text, pending[0].ID) {
		t.Fatalf("pending = %+v; the text for the client must not name the request: %s", pending, text)
	}
	if err := f.approvals.Decide(context.Background(), pending[0].ID, true, "admin-1"); err != nil {
		t.Fatalf("decide: %v", err)
	}

	text, isError = call(t, session, "light_turn_on", args)
	if isError || !strings.Contains(text, `"called":"light.turn_on"`) || f.core.countOf("call_service") != 1 {
		t.Fatalf("call after approval: isError = %t, %d service calls, %s", isError, f.core.countOf("call_service"), text)
	}
	if audited := f.auditText(t); !strings.Contains(audited, `"event":"action_approved"`) || !strings.Contains(audited, `"approver":"admin-1"`) {
		t.Fatalf("audit log:\n%s", audited)
	}
}
