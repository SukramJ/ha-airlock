// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package oauth_test

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/SukramJ/ha-airlock/internal/approval"
	"github.com/SukramJ/ha-airlock/internal/audit"
	"github.com/SukramJ/ha-airlock/internal/oauth"
	"github.com/SukramJ/ha-airlock/internal/policy"
)

// fakeFetcher knows one client.
type fakeFetcher struct{}

func (fakeFetcher) Fetch(_ context.Context, id string) (oauth.ClientMetadata, error) {
	if id != clientID {
		return oauth.ClientMetadata{}, oauth.ErrInvalidClient
	}
	return oauth.ClientMetadata{ClientID: clientID, ClientName: "Test <Client>", RedirectURIs: []string{redirectURI, "https://app.example/cb"}}, nil
}

type web struct {
	*fixture
	public  *httptest.Server
	consent *httptest.Server
	server  *oauth.Server
	client  *http.Client
	halt    *fakeSwitch
	actions *approval.Store
}

// fakeSwitch is a kill switch that remembers who operated it.
type fakeSwitch struct {
	engaged bool
	by      []string
}

func (f *fakeSwitch) Engaged() bool { return f.engaged }

func (f *fakeSwitch) Set(_ context.Context, engage bool, by string) error {
	f.engaged = engage
	f.by = append(f.by, by)
	return nil
}

func newWeb(t *testing.T) *web {
	t.Helper()
	w := &web{fixture: newFixture(t)}
	logger := slog.New(slog.DiscardHandler)

	publicMux := http.NewServeMux()
	w.public = httptest.NewServer(publicMux)
	t.Cleanup(w.public.Close)
	w.server = oauth.NewServer(w.store, fakeFetcher{}, w.public.URL, logger)
	w.server.Register(publicMux)

	w.halt = &fakeSwitch{}
	w.actions = approval.New(w.auditLog, nil)
	consent, err := oauth.NewConsent(w.store, w.halt, w.auditLog, w.actions, logger)
	if err != nil {
		t.Fatalf("consent: %v", err)
	}
	consentMux := http.NewServeMux()
	consent.Register(consentMux)
	w.consent = httptest.NewServer(consentMux)
	t.Cleanup(w.consent.Close)

	// The test plays the browser and must see every redirect itself.
	w.client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return w
}

func (w *web) authorizeURL(change func(url.Values)) string {
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI}, "state": {"state-1"},
		"code_challenge": {challengeOf(verifier)}, "code_challenge_method": {"S256"}, "resource": {w.server.Resource()},
	}
	if change != nil {
		change(q)
	}
	return w.public.URL + oauth.PathAuthorize + "?" + q.Encode()
}

// reply is what a test keeps of an HTTP response.
type reply struct {
	status int
	header http.Header
}

func (w *web) do(t *testing.T, req *http.Request) (resp reply, body string) {
	t.Helper()
	httpResp, err := w.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer func() { _ = httpResp.Body.Close() }()
	raw, err := io.ReadAll(httpResp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return reply{status: httpResp.StatusCode, header: httpResp.Header}, string(raw)
}

func (w *web) get(t *testing.T, target string) (resp reply, body string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	return w.do(t, req)
}

// asAdmin sends a request to the consent page the way the Supervisor does.
func (w *web) asAdmin(t *testing.T, method, path string, form url.Values) (resp reply, body string) {
	t.Helper()
	return w.consentRequest(t, method, path, form, admin, "system-admin,system-users")
}

func (w *web) consentRequest(t *testing.T, method, path string, form url.Values, userID, groups string) (resp reply, body string) {
	t.Helper()
	var payload io.Reader = http.NoBody
	if form != nil {
		payload = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(context.Background(), method, w.consent.URL+path, payload)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if userID != "" {
		req.Header.Set("X-Remote-User-Id", userID)
	}
	if groups != "" {
		req.Header.Set("X-Remote-User-Groups", groups)
	}
	return w.do(t, req)
}

var (
	codePattern = regexp.MustCompile(`[A-Z2-9]{4}-[A-Z2-9]{4}`)
	csrfPattern = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
)

// start sends the authorization request and returns the waiting address and
// the user code the waiting page shows.
func (w *web) start(t *testing.T) (waitURL, userCode string) {
	t.Helper()
	resp, _ := w.get(t, w.authorizeURL(nil))
	if resp.status != http.StatusSeeOther {
		t.Fatalf("authorize: status %d", resp.status)
	}
	waitURL = resp.header.Get("Location")
	resp, body := w.get(t, waitURL)
	if resp.status != http.StatusOK {
		t.Fatalf("wait: status %d", resp.status)
	}
	userCode = codePattern.FindString(body)
	if userCode == "" {
		t.Fatalf("the waiting page shows no code:\n%s", body)
	}
	return waitURL, userCode
}

func (w *web) csrf(t *testing.T) string {
	t.Helper()
	_, body := w.asAdmin(t, http.MethodGet, "/", nil)
	m := csrfPattern.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("the consent page has no form token:\n%s", body)
	}
	return m[1]
}

func (w *web) postToken(t *testing.T, form url.Values) (resp reply, fields map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, w.public.URL+oauth.PathToken, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, body := w.do(t, req)
	if err := json.Unmarshal([]byte(body), &fields); err != nil {
		t.Fatalf("token response is not JSON: %s", body)
	}
	return resp, fields
}

func TestMetadataDescribesWhatTheServerDoes(t *testing.T) {
	t.Parallel()
	w := newWeb(t)

	_, body := w.get(t, w.public.URL+oauth.PathServerMetadata)
	var as map[string]any
	if err := json.Unmarshal([]byte(body), &as); err != nil {
		t.Fatalf("server metadata: %v", err)
	}
	if as["issuer"] != w.public.URL || as["authorization_endpoint"] != w.public.URL+oauth.PathAuthorize ||
		as["token_endpoint"] != w.public.URL+oauth.PathToken ||
		as["client_id_metadata_document_supported"] != true ||
		as["authorization_response_iss_parameter_supported"] != true ||
		!strings.Contains(body, `"code_challenge_methods_supported":["S256"]`) {
		t.Fatalf("server metadata = %s", body)
	}
	if _, has := as["registration_endpoint"]; has {
		t.Fatal("the metadata offers dynamic client registration")
	}

	for _, path := range []string{oauth.PathResourceMetadata, oauth.PathResourceMetadata + oauth.PathMCP} {
		_, body := w.get(t, w.public.URL+path)
		var rs struct {
			Resource             string   `json:"resource"`
			AuthorizationServers []string `json:"authorization_servers"`
		}
		if err := json.Unmarshal([]byte(body), &rs); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if rs.Resource != w.public.URL+oauth.PathMCP || len(rs.AuthorizationServers) != 1 || rs.AuthorizationServers[0] != w.public.URL {
			t.Fatalf("%s = %s", path, body)
		}
	}
}

func TestApprovalInTheConsentPageLetsTheWaitingBrowserFinish(t *testing.T) {
	t.Parallel()
	w := newWeb(t)
	waitURL, userCode := w.start(t)

	_, page := w.asAdmin(t, http.MethodGet, "/", nil)
	if !strings.Contains(page, userCode) || !strings.Contains(page, "client.example") || !strings.Contains(page, "127.0.0.1:33418") {
		t.Fatalf("the consent page does not show the request:\n%s", page)
	}
	if strings.Contains(page, "Test <Client>") || !strings.Contains(page, "Test &lt;Client&gt;") {
		t.Fatal("the client's name is not escaped on the consent page")
	}
	resp, _ := w.asAdmin(t, http.MethodPost, "/decide", url.Values{
		"csrf": {w.csrf(t)}, "code": {userCode}, "action": {"approve"}, "profile": {policy.ProfileLocal},
	})
	if resp.status != http.StatusOK {
		t.Fatalf("decide: status %d", resp.status)
	}

	resp, _ = w.get(t, waitURL)
	if resp.status != http.StatusFound {
		t.Fatalf("wait after approval: status %d", resp.status)
	}
	target, err := url.Parse(resp.header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := target.Query()
	if !strings.HasPrefix(target.String(), redirectURI+"?") || q.Get("state") != "state-1" || q.Get("iss") != w.public.URL || q.Get("code") == "" {
		t.Fatalf("redirect = %s", target)
	}

	tokenResp, tokens := w.postToken(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "client_id": {clientID},
		"code_verifier": {verifier}, "redirect_uri": {redirectURI}, "resource": {w.server.Resource()},
	})
	if tokenResp.status != http.StatusOK || tokenResp.header.Get("Cache-Control") != "no-store" || tokens["token_type"] != "Bearer" {
		t.Fatalf("token response: %d %v", tokenResp.status, tokens)
	}
	accessToken, _ := tokens["access_token"].(string)
	info, err := w.server.Verifier()(context.Background(), accessToken, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if info.UserID != clientID {
		t.Fatalf("token info = %+v", info)
	}

	_, refreshed := w.postToken(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}, "client_id": {clientID},
	})
	if refreshed["access_token"] == nil || refreshed["refresh_token"] == tokens["refresh_token"] {
		t.Fatalf("refresh response = %v", refreshed)
	}
}

func TestWaitingPageIsNotCachedFramedOrLeakedAsReferrer(t *testing.T) {
	t.Parallel()
	w := newWeb(t)
	waitURL, _ := w.start(t)

	resp, _ := w.get(t, waitURL)

	for header, want := range map[string]string{
		"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY", "Refresh": "3",
	} {
		if got := resp.header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

func TestDenialSendsTheClientAnError(t *testing.T) {
	t.Parallel()
	w := newWeb(t)
	waitURL, userCode := w.start(t)
	w.asAdmin(t, http.MethodPost, "/decide", url.Values{"csrf": {w.csrf(t)}, "code": {userCode}, "action": {"deny"}})

	resp, _ := w.get(t, waitURL)

	target, _ := url.Parse(resp.header.Get("Location"))
	if resp.status != http.StatusFound || target.Query().Get("error") != "access_denied" || target.Query().Get("code") != "" {
		t.Fatalf("after denial: %d %s", resp.status, target)
	}
}

func TestAuthorizeShowsAnErrorAndRedirectsNowhereWhenClientOrRedirectIsWrong(t *testing.T) {
	t.Parallel()
	w := newWeb(t)
	cases := map[string]func(url.Values){
		"unknown client":         func(q url.Values) { q.Set("client_id", "https://unknown.example/metadata.json") },
		"unregistered redirect":  func(q url.Values) { q.Set("redirect_uri", "https://evil.example/cb") },
		"no redirect of several": func(q url.Values) { q.Del("redirect_uri") },
		"repeated parameter":     func(q url.Values) { q.Add("redirect_uri", "https://evil.example/cb") },
	}
	for name, change := range cases {
		resp, _ := w.get(t, w.authorizeURL(change))
		if resp.status != http.StatusBadRequest || resp.header.Get("Location") != "" {
			t.Errorf("%s: status %d, Location %q", name, resp.status, resp.header.Get("Location"))
		}
	}
	if len(w.store.PendingRequests()) != 0 {
		t.Fatal("a refused request was parked")
	}
}

func TestAuthorizeReportsOtherErrorsToTheClient(t *testing.T) {
	t.Parallel()
	w := newWeb(t)
	cases := map[string]struct {
		change func(url.Values)
		want   string
	}{
		"no code challenge":   {func(q url.Values) { q.Del("code_challenge") }, "invalid_request"},
		"plain challenge":     {func(q url.Values) { q.Set("code_challenge_method", "plain") }, "invalid_request"},
		"no challenge method": {func(q url.Values) { q.Del("code_challenge_method") }, "invalid_request"},
		"another resource":    {func(q url.Values) { q.Set("resource", "https://other.example/mcp") }, "invalid_target"},
		"no resource":         {func(q url.Values) { q.Del("resource") }, "invalid_target"},
		"implicit grant":      {func(q url.Values) { q.Set("response_type", "token") }, "unsupported_response_type"},
	}
	for name, c := range cases {
		resp, _ := w.get(t, w.authorizeURL(c.change))
		target, _ := url.Parse(resp.header.Get("Location"))
		if resp.status != http.StatusFound || !strings.HasPrefix(target.String(), redirectURI) ||
			target.Query().Get("error") != c.want || target.Query().Get("state") != "state-1" {
			t.Errorf("%s: %d %s", name, resp.status, target)
		}
	}
	if len(w.store.PendingRequests()) != 0 {
		t.Fatal("a refused request was parked")
	}
}

func TestTokenEndpointRefusesBadRequests(t *testing.T) {
	t.Parallel()
	w := newWeb(t)
	cases := map[string]struct {
		form url.Values
		want string
	}{
		"unknown code":       {url.Values{"grant_type": {"authorization_code"}, "code": {"nope"}, "client_id": {clientID}, "code_verifier": {verifier}}, "invalid_grant"},
		"unknown refresh":    {url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"nope"}, "client_id": {clientID}}, "invalid_grant"},
		"password grant":     {url.Values{"grant_type": {"password"}, "username": {"a"}, "password": {"b"}}, "unsupported_grant_type"},
		"client credentials": {url.Values{"grant_type": {"client_credentials"}}, "unsupported_grant_type"},
		"repeated parameter": {url.Values{"grant_type": {"authorization_code"}, "code": {"a", "b"}}, "invalid_request"},
	}
	for name, c := range cases {
		resp, body := w.postToken(t, c.form)
		if resp.status != http.StatusBadRequest || body["error"] != c.want || resp.header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %v", name, resp.status, body)
		}
	}
}

func TestConsentPageServesAdministratorsOnly(t *testing.T) {
	t.Parallel()
	w := newWeb(t)
	_, userCode := w.start(t)
	token := w.csrf(t)
	approve := url.Values{"csrf": {token}, "code": {userCode}, "action": {"approve"}, "profile": {policy.ProfileLocal}}

	callers := map[string][2]string{
		"no user":          {"", ""},
		"user, no groups":  {"some-user", ""},
		"user, not admin":  {"some-user", "system-users"},
		"groups, no user":  {"", "system-admin"},
		"admin-like group": {"some-user", "not-system-admin,system-admins"},
	}
	for name, c := range callers {
		if resp, _ := w.consentRequest(t, http.MethodGet, "/", nil, c[0], c[1]); resp.status != http.StatusForbidden {
			t.Errorf("%s: page status %d, want 403", name, resp.status)
		}
		if resp, _ := w.consentRequest(t, http.MethodPost, "/decide", approve, c[0], c[1]); resp.status != http.StatusForbidden {
			t.Errorf("%s: decide status %d, want 403", name, resp.status)
		}
	}
	if pending := w.store.PendingRequests(); len(pending) != 1 {
		t.Fatalf("the request was decided by someone who is not an administrator: %+v", pending)
	}
}

func TestConsentFormsNeedThePagesOwnToken(t *testing.T) {
	t.Parallel()
	w := newWeb(t)
	_, userCode := w.start(t)

	for name, token := range map[string]string{"missing": "", "wrong": "not-the-token"} {
		resp, _ := w.asAdmin(t, http.MethodPost, "/decide", url.Values{
			"csrf": {token}, "code": {userCode}, "action": {"approve"}, "profile": {policy.ProfileLocal},
		})
		if resp.status != http.StatusForbidden {
			t.Errorf("%s token: status %d, want 403", name, resp.status)
		}
	}
	if len(w.store.PendingRequests()) != 1 {
		t.Fatal("a forged form decided the request")
	}
}

func TestRevokingOnTheConsentPageEndsAccess(t *testing.T) {
	t.Parallel()
	w := newWeb(t)
	tokens := w.tokens(t, policy.ProfileLocal)
	grant := w.store.Grants()[0]

	resp, body := w.asAdmin(t, http.MethodPost, "/revoke", url.Values{"csrf": {w.csrf(t)}, "grant": {grant.ID}})

	if resp.status != http.StatusOK || !strings.Contains(body, "Access revoked") {
		t.Fatalf("revoke: %d\n%s", resp.status, body)
	}
	if _, err := w.server.Verifier()(context.Background(), tokens.AccessToken, nil); err == nil {
		t.Fatal("the access token works after revocation")
	}
}

func TestKillSwitchIsOperatedFromTheConsentPageByAnAdministrator(t *testing.T) {
	t.Parallel()
	w := newWeb(t)
	token := w.csrf(t)

	resp, body := w.asAdmin(t, http.MethodPost, "/halt", url.Values{"csrf": {token}, "action": {"engage"}})
	if resp.status != http.StatusOK || !w.halt.engaged || !strings.Contains(body, "ha-airlock is halted") {
		t.Fatalf("engage: status %d, engaged %t", resp.status, w.halt.engaged)
	}
	resp, body = w.asAdmin(t, http.MethodPost, "/halt", url.Values{"csrf": {token}, "action": {"release"}})
	if resp.status != http.StatusOK || w.halt.engaged || strings.Contains(body, "ha-airlock is halted") {
		t.Fatalf("release: status %d, engaged %t", resp.status, w.halt.engaged)
	}
	if len(w.halt.by) != 2 || w.halt.by[0] != admin {
		t.Fatalf("operated by %v", w.halt.by)
	}

	// Not an administrator, and an administrator without the page's token.
	if resp, _ := w.consentRequest(t, http.MethodPost, "/halt", url.Values{"csrf": {token}, "action": {"engage"}}, "some-user", "system-users"); resp.status != http.StatusForbidden {
		t.Errorf("non-administrator: status %d, want 403", resp.status)
	}
	if resp, _ := w.asAdmin(t, http.MethodPost, "/halt", url.Values{"csrf": {"wrong"}, "action": {"engage"}}); resp.status != http.StatusForbidden {
		t.Errorf("forged form: status %d, want 403", resp.status)
	}
	if w.halt.engaged {
		t.Fatal("the kill switch was operated without authority")
	}
}

func TestAuditPageShowsTheLogToAdministratorsOnly(t *testing.T) {
	t.Parallel()
	w := newWeb(t)
	w.tokens(t, policy.ProfileLocal)

	resp, body := w.asAdmin(t, http.MethodGet, "/audit", nil)
	if resp.status != http.StatusOK || !strings.Contains(body, "client_approved") || !strings.Contains(body, "by "+admin) {
		t.Fatalf("audit page: status %d\n%s", resp.status, body)
	}
	if !strings.Contains(body, "The chain holds") || strings.Contains(body, "not intact") {
		t.Fatalf("the page does not report an intact log:\n%s", body)
	}
	if csp := resp.header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || resp.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("headers: %v", resp.header)
	}

	for name, c := range map[string][2]string{"no user": {"", ""}, "not admin": {"some-user", "system-users"}} {
		if resp, body := w.consentRequest(t, http.MethodGet, "/audit", nil, c[0], c[1]); resp.status != http.StatusForbidden || strings.Contains(body, "client_approved") {
			t.Errorf("%s: status %d, want 403 and no record", name, resp.status)
		}
	}
	if resp, _ := w.asAdmin(t, http.MethodGet, "/audit?before=newest", nil); resp.status != http.StatusBadRequest {
		t.Errorf("a record number that is none: status %d, want 400", resp.status)
	}
}

// What the log holds was written by clients and by Home Assistant; the page
// must show it as text.
func TestAuditPageShowsRecordedTextAsTextNotAsMarkup(t *testing.T) {
	t.Parallel()
	w := newWeb(t)
	hostile := `<script>alert(1)</script><img src=x onerror=alert(2)>`
	_, err := w.auditLog.Append(context.Background(), audit.Entry{
		Event: "tool_call", Client: hostile, Tool: hostile, Decision: hostile, Approver: hostile, Result: hostile,
		Arguments: json.RawMessage(`{"q":"</code><script>alert(3)</script>"}`),
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	_, body := w.asAdmin(t, http.MethodGet, "/audit", nil)

	if strings.Contains(body, "<script") || strings.Contains(body, "<img") {
		t.Fatalf("recorded text reached the page as markup:\n%s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)") || !strings.Contains(body, "alert(3)") {
		t.Fatalf("the record is not shown:\n%s", body)
	}
}

func TestAuditPageLeadsBackThroughOlderRecords(t *testing.T) {
	t.Parallel()
	w := newWeb(t)
	for range 130 {
		if _, err := w.auditLog.Append(context.Background(), audit.Entry{Event: "tool_call", Tool: "system_log_list"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	_, newest := w.asAdmin(t, http.MethodGet, "/audit", nil)
	if !strings.Contains(newest, "<td>130</td>") || !strings.Contains(newest, "<td>31</td>") || strings.Contains(newest, "<td>30</td>") {
		t.Fatalf("the newest page does not hold records 130 to 31:\n%s", newest)
	}
	if !strings.Contains(newest, `href="audit?before=31"`) {
		t.Fatalf("the newest page has no link to older records:\n%s", newest)
	}
	_, older := w.asAdmin(t, http.MethodGet, "/audit?before=31", nil)
	if !strings.Contains(older, "<td>30</td>") || !strings.Contains(older, "<td>1</td>") || strings.Contains(older, "<td>31</td>") || strings.Contains(older, "Older records") {
		t.Fatalf("the older page does not hold records 30 to 1 and nothing else:\n%s", older)
	}
}

func TestAuditPageShortensLongArguments(t *testing.T) {
	t.Parallel()
	w := newWeb(t)
	long := `{"q":"` + strings.Repeat("ä", 600) + `END"}`
	if _, err := w.auditLog.Append(context.Background(), audit.Entry{Event: "tool_call", Arguments: json.RawMessage(long)}); err != nil {
		t.Fatalf("append: %v", err)
	}
	_, body := w.asAdmin(t, http.MethodGet, "/audit", nil)
	if strings.Contains(body, "END") || !strings.Contains(body, "ää …") || strings.Contains(body, "\uFFFD") {
		t.Fatalf("long arguments are not shortened cleanly:\n%s", body)
	}
}

func TestAuditPageSaysWhenTheLogIsNotIntact(t *testing.T) {
	t.Parallel()
	w := newWeb(t)
	w.tokens(t, policy.ProfileLocal)
	if _, err := w.auditLog.Append(context.Background(), audit.Entry{Event: "tool_call", Tool: "last_tool"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	data, err := os.ReadFile(w.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(strings.TrimSuffix(string(data), "\n"), "\n")
	if err := os.WriteFile(w.auditPath, []byte(strings.Join(lines[:len(lines)-1], "")), 0o600); err != nil {
		t.Fatal(err)
	}

	resp, body := w.asAdmin(t, http.MethodGet, "/audit", nil)

	if resp.status != http.StatusOK || !strings.Contains(body, "The audit log is not intact") || strings.Contains(body, "The chain holds") {
		t.Fatalf("status %d\n%s", resp.status, body)
	}
	if !strings.Contains(body, "client_approved") || strings.Contains(body, "last_tool") {
		t.Fatalf("the page does not show exactly the records that are left:\n%s", body)
	}
}

// park puts one action before the owner and returns it.
func (w *web) park(t *testing.T, client, name string) approval.Request {
	t.Helper()
	args := json.RawMessage(`{"entity_id":"light.kitchen"}`)
	key, err := approval.Key(client, "light_turn_on", args)
	if err != nil {
		t.Fatal(err)
	}
	req := &approval.Request{
		Key: key, Client: client, Tool: "light_turn_on", Summary: "Turn on light.kitchen", Arguments: args,
		Entities: []approval.Entity{{ID: "light.kitchen", Name: name}},
	}
	if status, _, err := w.actions.Resolve(context.Background(), req); err != nil || status != approval.Waiting {
		t.Fatalf("park: status %d, %v", status, err)
	}
	pending := w.actions.Pending()
	for i := range pending {
		if pending[i].Key == key {
			return pending[i]
		}
	}
	t.Fatal("the parked action is not pending")
	return approval.Request{}
}

func (w *web) status(t *testing.T, r approval.Request) approval.Status {
	t.Helper()
	status, _, err := w.actions.Resolve(context.Background(), &r)
	if err != nil {
		t.Fatal(err)
	}
	return status
}

func TestWaitingActionIsShownAndApprovedOnThePageByAnAdministrator(t *testing.T) {
	t.Parallel()
	w := newWeb(t)
	w.tokens(t, policy.ProfileLocal)
	parked := w.park(t, clientID, `Kitchen <b>ceiling</b>`)

	_, body := w.asAdmin(t, http.MethodGet, "/", nil)
	for _, want := range []string{
		"Turn on light.kitchen", "light.kitchen — Kitchen &lt;b&gt;ceiling&lt;/b&gt;", html.EscapeString(w.store.Grants()[0].ClientName) + " (", "light_turn_on",
		`name="id" value="` + parked.ID + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Contains(body, "<b>ceiling") || strings.Contains(body, parked.Key) {
		t.Fatalf("the page shows the entity name as markup, or the key:\n%s", body)
	}

	resp, body := w.asAdmin(t, http.MethodPost, "/action", url.Values{"csrf": {w.csrf(t)}, "id": {parked.ID}, "action": {"approve"}})
	if resp.status != http.StatusOK || !strings.Contains(body, "Approved. The action runs") || !strings.Contains(body, "No action is waiting") {
		t.Fatalf("approve: %d\n%s", resp.status, body)
	}
	if got := w.status(t, parked); got != approval.Approved {
		t.Fatalf("status after approval = %d", got)
	}
	if audited := w.auditText(t); !strings.Contains(audited, `"event":"action_approved"`) || !strings.Contains(audited, `"approver":"`+admin+`"`) {
		t.Fatalf("audit log:\n%s", audited)
	}
}

func TestActionIsDeniedOnThePage(t *testing.T) {
	t.Parallel()
	w := newWeb(t)
	parked := w.park(t, clientID, "")

	resp, body := w.asAdmin(t, http.MethodPost, "/action", url.Values{"csrf": {w.csrf(t)}, "id": {parked.ID}, "action": {"deny"}})

	if resp.status != http.StatusOK || !strings.Contains(body, "Denied. The action does not run") {
		t.Fatalf("deny: %d\n%s", resp.status, body)
	}
	if got := w.status(t, parked); got != approval.Denied {
		t.Fatalf("status after denial = %d", got)
	}
	// Anything but the word approve is a denial, and a request is decided once.
	_, body = w.asAdmin(t, http.MethodPost, "/action", url.Values{"csrf": {w.csrf(t)}, "id": {parked.ID}, "action": {"approve"}})
	if !strings.Contains(body, "expired or was already decided") || w.status(t, parked) != approval.Denied {
		t.Fatalf("a decided action was decided again:\n%s", body)
	}
}

func TestActionIsDecidedOnlyByAnAdministratorThroughThePagesOwnForm(t *testing.T) {
	t.Parallel()
	w := newWeb(t)
	parked := w.park(t, clientID, "")
	token := w.csrf(t)
	form := func(csrf string) url.Values {
		return url.Values{"csrf": {csrf}, "id": {parked.ID}, "action": {"approve"}}
	}

	if resp, _ := w.consentRequest(t, http.MethodPost, "/action", form(token), "some-user", "system-users"); resp.status != http.StatusForbidden {
		t.Errorf("non-administrator: status %d, want 403", resp.status)
	}
	if resp, _ := w.consentRequest(t, http.MethodPost, "/action", form(token), "", ""); resp.status != http.StatusForbidden {
		t.Errorf("nobody: status %d, want 403", resp.status)
	}
	if resp, _ := w.asAdmin(t, http.MethodPost, "/action", form("not-the-token")); resp.status != http.StatusForbidden {
		t.Errorf("forged form: status %d, want 403", resp.status)
	}
	if got := w.status(t, parked); got != approval.Waiting {
		t.Fatalf("the action was decided: status %d", got)
	}
}
