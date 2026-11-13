// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/SukramJ/ha-airlock/internal/mcpserver"
)

// MetadataFetcher retrieves a client's metadata document.
type MetadataFetcher interface {
	Fetch(ctx context.Context, clientID string) (ClientMetadata, error)
}

// Paths of the public endpoints, below the public URL.
const (
	PathAuthorize        = "/oauth/authorize"
	pathWait             = "/oauth/authorize/wait"
	PathToken            = "/oauth/token" //nolint:gosec // a URL path, not a credential
	PathServerMetadata   = "/.well-known/oauth-authorization-server"
	PathResourceMetadata = "/.well-known/oauth-protected-resource"
	// PathMCP is where the MCP server is served; with the public URL it is
	// the resource tokens are issued for.
	PathMCP = "/mcp"
)

// Server is the authorization server's HTTP side.
type Server struct {
	store   *Store
	fetcher MetadataFetcher
	// issuer is the public HTTPS URL of ha-airlock, without a trailing
	// slash. It identifies the authorization server.
	issuer string
	logger *slog.Logger
}

// NewServer returns the HTTP side over a store. issuer is the public URL.
func NewServer(store *Store, fetcher MetadataFetcher, issuer string, logger *slog.Logger) *Server {
	return &Server{store: store, fetcher: fetcher, issuer: issuer, logger: logger}
}

// Resource is the identifier of the MCP server that tokens are issued for.
func (s *Server) Resource() string { return s.issuer + PathMCP }

// ResourceMetadataURL is where a client finds the protected resource
// metadata; the MCP endpoint names it when it answers 401.
func (s *Server) ResourceMetadataURL() string { return s.issuer + PathResourceMetadata + PathMCP }

// Register adds the public endpoints to mux.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+PathServerMetadata, s.serverMetadata)
	resource := auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               s.Resource(),
		AuthorizationServers:   []string{s.issuer},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "ha-airlock",
	})
	// RFC 9728 puts the well-known part between host and the resource's
	// path; the bare form is served too for clients that look there.
	mux.Handle(PathResourceMetadata+PathMCP, resource)
	mux.Handle(PathResourceMetadata, resource)
	mux.HandleFunc("GET "+PathAuthorize, s.authorize)
	mux.HandleFunc("GET "+pathWait, s.wait)
	mux.HandleFunc("POST "+PathToken, s.token)
}

// Verifier returns the check the MCP endpoint applies to an access token.
func (s *Server) Verifier() auth.TokenVerifier {
	return func(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		identity, err := s.store.Verify(token)
		if err != nil {
			return nil, auth.ErrInvalidToken
		}
		return mcpserver.TokenInfo(identity.ClientID, identity.Profile, identity.Expiration), nil
	}
}

func (s *Server) serverMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{ // RFC 8414 metadata: heterogeneous values by definition
		"issuer":                                         s.issuer,
		"authorization_endpoint":                         s.issuer + PathAuthorize,
		"token_endpoint":                                 s.issuer + PathToken,
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"client_id_metadata_document_supported":          true,
		"authorization_response_iss_parameter_supported": true,
	})
}

// authorize validates an authorization request and parks it. It never
// decides anything: the decision is taken in the Ingress UI.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for name, values := range q {
		if len(values) > 1 {
			s.errorPage(w, "The request repeats the parameter "+name+".")
			return
		}
	}

	// Until client and redirect URI are established, an error is shown to
	// the person and never sent to a redirect URI.
	meta, err := s.fetcher.Fetch(r.Context(), q.Get("client_id"))
	if err != nil {
		s.logger.WarnContext(r.Context(), "authorization request refused", slog.Any("error", err))
		s.errorPage(w, "The application that sent you here could not be identified.")
		return
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" && len(meta.RedirectURIs) == 1 {
		redirectURI = meta.RedirectURIs[0]
	}
	if !MatchRedirect(meta.RedirectURIs, redirectURI) {
		s.errorPage(w, "The application asked to be answered at an address it has not registered.")
		return
	}

	// From here on the client is told about errors at its redirect URI.
	state := q.Get("state")
	switch {
	case q.Get("response_type") != "code":
		s.redirectError(w, r, redirectURI, state, "unsupported_response_type", "only response_type code is supported")
		return
	case q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256":
		s.redirectError(w, r, redirectURI, state, "invalid_request", "a code_challenge with method S256 is required")
		return
	case q.Get("resource") != s.Resource():
		s.redirectError(w, r, redirectURI, state, "invalid_target", "the resource parameter must name this server")
		return
	}

	pending, err := s.store.Park(&Request{
		ClientID: meta.ClientID, ClientName: meta.ClientName, RedirectURI: redirectURI,
		State: state, Challenge: q.Get("code_challenge"), Resource: s.Resource(),
	})
	if err != nil {
		s.redirectError(w, r, redirectURI, state, "temporarily_unavailable", "too many requests are waiting for approval")
		return
	}
	// The browser is sent to its own waiting address, so that reloading
	// does not park the request a second time.
	http.Redirect(w, r, s.issuer+pathWait+"?request="+url.QueryEscape(pending.ID), http.StatusSeeOther)
}

// wait is where the browser stays until the administrator has decided.
func (s *Server) wait(w http.ResponseWriter, r *http.Request) {
	pending, code, err := s.store.Collect(r.URL.Query().Get("request"))
	if err != nil {
		s.errorPage(w, "This request has expired or was already completed. Start again from the application.")
		return
	}
	switch pending.Status {
	case StatusApproved:
		target := withQuery(pending.Request.RedirectURI, url.Values{
			"code": {code}, "state": optional(pending.Request.State), "iss": {s.issuer},
		})
		s.redirect(w, r, target)
	case StatusDenied:
		s.redirectError(w, r, pending.Request.RedirectURI, pending.Request.State, "access_denied", "the request was denied")
	case StatusPending:
		securityHeaders(w)
		w.Header().Set("Refresh", "3")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := waitPage.Execute(w, map[string]string{
			"Code": pending.UserCode, "Client": pending.Request.ClientName, "ClientHost": hostOf(pending.Request.ClientID),
		}); err != nil {
			s.logger.WarnContext(r.Context(), "waiting page could not be written", slog.Any("error", err))
		}
	}
}

// token is the token endpoint.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		tokenError(w, "invalid_request")
		return
	}
	for _, values := range r.PostForm {
		if len(values) > 1 {
			tokenError(w, "invalid_request")
			return
		}
	}
	form := r.PostForm
	var (
		tokens Tokens
		err    error
	)
	switch form.Get("grant_type") {
	case "authorization_code":
		tokens, err = s.store.Exchange(r.Context(), form.Get("code"), form.Get("client_id"),
			form.Get("redirect_uri"), form.Get("resource"), form.Get("code_verifier"))
	case "refresh_token":
		tokens, err = s.store.Refresh(r.Context(), form.Get("refresh_token"), form.Get("client_id"))
	default:
		tokenError(w, "unsupported_grant_type")
		return
	}
	if errors.Is(err, ErrInvalidGrant) {
		tokenError(w, "invalid_grant")
		return
	}
	if err != nil {
		s.logger.ErrorContext(r.Context(), "token request failed", slog.Any("error", err))
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{ // OAuth token response: strings and a number
		"access_token":  tokens.AccessToken,
		"token_type":    "Bearer",
		"expires_in":    int(tokens.ExpiresIn / time.Second),
		"refresh_token": tokens.RefreshToken,
	})
}

func tokenError(w http.ResponseWriter, code string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": code})
}

// redirectError reports an error to the client at its redirect URI.
func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	s.redirect(w, r, withQuery(redirectURI, url.Values{
		"error": {code}, "error_description": {description}, "state": optional(state), "iss": {s.issuer},
	}))
}

func (s *Server) redirect(w http.ResponseWriter, r *http.Request, target string) {
	securityHeaders(w)
	// The target is a redirect URI that was matched against the client's
	// registered ones before the request was parked.
	http.Redirect(w, r, target, http.StatusFound) //nolint:gosec // see above
}

func (s *Server) errorPage(w http.ResponseWriter, message string) {
	securityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_ = errorPage.Execute(w, message)
}

// securityHeaders are set on every page and redirect of the authorization
// endpoint: nothing is cached, the page cannot be framed, and the request
// id in the address is not passed on as a referrer.
func securityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
}

// withQuery adds parameters to a URL, keeping the ones it has.
func withQuery(raw string, add url.Values) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	for name, values := range add {
		if len(values) > 0 {
			q.Set(name, values[0])
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// optional is a parameter that is sent only when it has a value.
func optional(value string) []string {
	if value == "" {
		return nil
	}
	return []string{value}
}

func writeJSON(w http.ResponseWriter, status int, value any) { //nolint:revive // value is a response body: any is the encoding/json contract
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// colours is the part of every page's style that sets its colours. A page
// states its own background and text colour for the light and for the dark
// scheme: inside Home Assistant it is shown in a frame, and must be
// readable whatever lies behind that frame.
const colours = `:root{color-scheme:light dark;--bg:#fff;--fg:#1c1c1c;--muted:#555;--line:#c8c8c8;--warn:#a40000;--ok:#1a6b1a;--note:#e8ebff;--link:#0b57d0}
@media (prefers-color-scheme:dark){:root{--bg:#1c1c1e;--fg:#e6e6e6;--muted:#a8a8a8;--line:#4a4a4a;--warn:#ff8a80;--ok:#7fd68a;--note:#2a3050;--link:#8ab4f8}}
html,body{background:var(--bg);color:var(--fg)}a{color:var(--link)}small{color:var(--muted)}.warn{color:var(--warn)}.ok{color:var(--ok)}
`

const pageStyle = `<style>` + colours + `body{font-family:system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;line-height:1.5}
.code{font-size:2rem;letter-spacing:.15em;font-weight:600;margin:1rem 0}</style>`

var waitPage = template.Must(template.New("wait").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ha-airlock: waiting for approval</title>` + pageStyle + `</head><body>
<h1>Waiting for approval</h1>
<p><strong>{{.Client}}</strong> ({{.ClientHost}}) asks for access to Home Assistant through ha-airlock.</p>
<p>Open <strong>ha-airlock</strong> in the Home Assistant sidebar and approve the request that shows this code:</p>
<p class="code">{{.Code}}</p>
<p><small>Approve only if you started this yourself and the code matches. This page continues on its own once you have decided. The request expires after ten minutes.</small></p>
</body></html>`))

var errorPage = template.Must(template.New("error").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ha-airlock: request refused</title>` + pageStyle + `</head><body>
<h1>Request refused</h1><p>{{.}}</p></body></html>`))
