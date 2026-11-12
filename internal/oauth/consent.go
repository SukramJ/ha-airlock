// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package oauth

import (
	"crypto/subtle"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/SukramJ/ha-airlock/internal/policy"
)

// Headers the Supervisor sets on a request it passes through Ingress, after
// removing whatever the browser sent under these names.
const (
	headerUserID     = "X-Remote-User-Id"
	headerUserGroups = "X-Remote-User-Groups"
	adminGroup       = "system-admin"
)

// Consent is the page in Home Assistant's sidebar on which an administrator
// approves, denies and revokes clients.
//
// It trusts the user headers, and so must be served only to the
// Supervisor: the listener it is mounted on accepts no other peer.
type Consent struct {
	store  *Store
	csrf   string
	logger *slog.Logger
}

// NewConsent returns the consent page over a store.
func NewConsent(store *Store, logger *slog.Logger) (*Consent, error) {
	csrf, err := randomToken()
	if err != nil {
		return nil, err
	}
	return &Consent{store: store, csrf: csrf, logger: logger}, nil
}

// Register adds the consent page to mux. The paths are relative to the
// address Ingress gives the App.
func (c *Consent) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", c.page)
	mux.HandleFunc("POST /decide", c.decide)
	mux.HandleFunc("POST /revoke", c.revoke)
}

// administrator returns the Home Assistant user behind a request, if the
// Supervisor named one and that user is an administrator.
func administrator(r *http.Request) (id string, ok bool) {
	id = r.Header.Get(headerUserID)
	if id == "" {
		return "", false
	}
	for _, group := range strings.Split(r.Header.Get(headerUserGroups), ",") {
		if strings.TrimSpace(group) == adminGroup {
			return id, true
		}
	}
	return "", false
}

func (c *Consent) page(w http.ResponseWriter, r *http.Request) {
	if _, ok := administrator(r); !ok {
		http.Error(w, "Only a Home Assistant administrator can manage ha-airlock.", http.StatusForbidden)
		return
	}
	c.render(w, r, "")
}

func (c *Consent) render(w http.ResponseWriter, r *http.Request, message string) {
	type pendingView struct {
		Code, Client, ClientHost, RedirectHost string
		Loopback                               bool
		Age                                    string
	}
	type grantView struct {
		ID, Client, ClientHost, Profile, Created, LastUsed string
	}
	view := struct {
		CSRF, Message string
		Pending       []pendingView
		Grants        []grantView
		Profiles      []string
	}{CSRF: c.csrf, Message: message, Profiles: []string{policy.ProfileLocal, policy.ProfileRemote}}
	now := time.Now()
	pending := c.store.PendingRequests()
	for i := range pending {
		p := &pending[i]
		view.Pending = append(view.Pending, pendingView{
			Code: p.UserCode, Client: p.Request.ClientName, ClientHost: hostOf(p.Request.ClientID),
			RedirectHost: hostOf(p.Request.RedirectURI), Loopback: strings.HasPrefix(p.Request.RedirectURI, "http://"),
			Age: now.Sub(p.CreatedAt).Round(time.Second).String(),
		})
	}
	grants := c.store.Grants()
	for i := range grants {
		g := &grants[i]
		view.Grants = append(view.Grants, grantView{
			ID: g.ID, Client: g.ClientName, ClientHost: hostOf(g.ClientID), Profile: g.Profile,
			Created: g.CreatedAt.Format("2006-01-02 15:04"), LastUsed: g.LastUsed.Format("2006-01-02 15:04"),
		})
	}
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
	h.Set("Content-Type", "text/html; charset=utf-8")
	if err := consentPage.Execute(w, view); err != nil {
		c.logger.WarnContext(r.Context(), "consent page could not be written", slog.Any("error", err))
	}
}

// checked reports whether a POST comes from an administrator and from the
// consent page itself.
func (c *Consent) checked(w http.ResponseWriter, r *http.Request) (userID string, ok bool) {
	userID, ok = administrator(r)
	if !ok {
		http.Error(w, "Only a Home Assistant administrator can manage ha-airlock.", http.StatusForbidden)
		return "", false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "The form could not be read.", http.StatusBadRequest)
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(c.csrf)) != 1 {
		http.Error(w, "The form is out of date. Open ha-airlock again.", http.StatusForbidden)
		return "", false
	}
	return userID, true
}

func (c *Consent) decide(w http.ResponseWriter, r *http.Request) {
	userID, ok := c.checked(w, r)
	if !ok {
		return
	}
	approve := r.PostForm.Get("action") == "approve"
	err := c.store.Decide(r.Context(), r.PostForm.Get("code"), approve, r.PostForm.Get("profile"), userID)
	switch {
	case errors.Is(err, ErrUnknownRequest):
		c.render(w, r, "That request has expired or was already decided.")
	case err != nil:
		c.logger.ErrorContext(r.Context(), "decision failed", slog.Any("error", err))
		c.render(w, r, "The decision could not be recorded and did not take effect.")
	case approve:
		c.render(w, r, "Approved. The application continues on its own.")
	default:
		c.render(w, r, "Denied.")
	}
}

func (c *Consent) revoke(w http.ResponseWriter, r *http.Request) {
	userID, ok := c.checked(w, r)
	if !ok {
		return
	}
	if err := c.store.Revoke(r.Context(), r.PostForm.Get("grant"), "user "+userID); err != nil {
		c.render(w, r, "That client is not approved any more.")
		return
	}
	c.render(w, r, "Access revoked.")
}

var consentPage = template.Must(template.New("consent").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ha-airlock</title>
<style>body{font-family:system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem;line-height:1.5}
section{border:1px solid #ccc;border-radius:.5rem;padding:1rem;margin:1rem 0}.code{font-size:1.6rem;letter-spacing:.15em;font-weight:600}
.warn{color:#a40000}.msg{background:#eef;padding:.6rem 1rem;border-radius:.5rem}button{font-size:1rem;padding:.4rem .9rem;margin-right:.5rem}
dt{font-weight:600}dd{margin:0 0 .4rem 0}small{color:#555}</style></head><body>
<h1>ha-airlock</h1>
<p><a href="./">Reload</a></p>
{{if .Message}}<p class="msg">{{.Message}}</p>{{end}}
<h2>Waiting for your approval</h2>
{{range .Pending}}<section>
<p class="code">{{.Code}}</p>
<dl><dt>Application</dt><dd>{{.Client}}</dd>
<dt>Identified by</dt><dd>{{.ClientHost}}</dd>
<dt>Answer goes to</dt><dd>{{.RedirectHost}}{{if .Loopback}} <span class="warn">— an address on the computer running the application. Any program on that computer can claim to be this application.</span>{{end}}</dd>
<dt>Waiting since</dt><dd>{{.Age}}</dd></dl>
<p><small>Approve only if you started this yourself just now and the code above is the one your browser shows.</small></p>
<form method="post" action="decide"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="code" value="{{.Code}}">
<label>Profile <select name="profile">{{range $.Profiles}}<option>{{.}}</option>{{end}}</select></label>
<button name="action" value="approve">Approve</button><button name="action" value="deny">Deny</button></form>
</section>{{else}}<p>No application is waiting.</p>{{end}}
<h2>Approved applications</h2>
{{range .Grants}}<section><dl><dt>Application</dt><dd>{{.Client}} ({{.ClientHost}})</dd>
<dt>Profile</dt><dd>{{.Profile}}</dd><dt>Approved</dt><dd>{{.Created}}</dd><dt>Last used</dt><dd>{{.LastUsed}}</dd></dl>
<form method="post" action="revoke"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="grant" value="{{.ID}}">
<button>Revoke access</button></form></section>{{else}}<p>No application is approved.</p>{{end}}
</body></html>`))
