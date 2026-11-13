// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package oauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/SukramJ/ha-airlock/internal/audit"
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
	halt   KillSwitch
	audit  Journal
	csrf   string
	logger *slog.Logger
}

// KillSwitch is the switch the page shows and operates.
type KillSwitch interface {
	Engaged() bool
	Set(ctx context.Context, engage bool, by string) error
}

// Journal is the audit log the page shows.
type Journal interface {
	Read(ctx context.Context, before uint64, limit int) (audit.Page, error)
}

// NewConsent returns the consent page over a store, the kill switch and the
// audit log.
func NewConsent(store *Store, killSwitch KillSwitch, journal Journal, logger *slog.Logger) (*Consent, error) {
	csrf, err := randomToken()
	if err != nil {
		return nil, err
	}
	return &Consent{store: store, halt: killSwitch, audit: journal, csrf: csrf, logger: logger}, nil
}

// Register adds the consent page to mux. The paths are relative to the
// address Ingress gives the App.
func (c *Consent) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", c.page)
	mux.HandleFunc("GET /audit", c.auditPage)
	mux.HandleFunc("POST /decide", c.decide)
	mux.HandleFunc("POST /revoke", c.revoke)
	mux.HandleFunc("POST /halt", c.setHalt)
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
		Halted        bool
		Pending       []pendingView
		Grants        []grantView
		Profiles      []string
	}{CSRF: c.csrf, Message: message, Halted: c.halt.Engaged(), Profiles: []string{policy.ProfileLocal, policy.ProfileRemote}}
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
	c.write(w, r, consentPage, view)
}

// write sends one of the pages. Nothing on them comes from anywhere but
// this server: no script, no image, no frame.
func (c *Consent) write(w http.ResponseWriter, r *http.Request, page *template.Template, view any) { // any: each page has its own view struct
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
	h.Set("Content-Type", "text/html; charset=utf-8")
	if err := page.Execute(w, view); err != nil {
		c.logger.WarnContext(r.Context(), "page could not be written", slog.Any("error", err))
	}
}

const (
	// auditPageSize is the number of records one audit page shows.
	auditPageSize = 100
	// auditArgumentsShown bounds the arguments shown for one record; the
	// file holds them in full.
	auditArgumentsShown = 400
)

// auditPage shows the audit log, newest record first. The log holds what
// clients sent and what Home Assistant answered; the template escapes all
// of it.
func (c *Consent) auditPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := administrator(r); !ok {
		http.Error(w, "Only a Home Assistant administrator can manage ha-airlock.", http.StatusForbidden)
		return
	}
	var before uint64
	if raw := r.URL.Query().Get("before"); raw != "" {
		n, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			http.Error(w, "That is not a record number.", http.StatusBadRequest)
			return
		}
		before = n
	}
	type recordView struct {
		Seq                                                                  uint64
		Time, Event, Client, Tool, Decision, Approver, Result, Arguments, MS string
	}
	view := struct {
		Records  []recordView
		Verified uint64
		Broken   string
		Older    uint64
		Paged    bool
	}{Paged: before != 0}
	page, err := c.audit.Read(r.Context(), before, auditPageSize)
	switch {
	case errors.Is(err, audit.ErrBroken):
		view.Broken = err.Error()
	case err != nil:
		c.logger.ErrorContext(r.Context(), "audit log could not be read", slog.Any("error", err))
		http.Error(w, "The audit log could not be read.", http.StatusInternalServerError)
		return
	}
	view.Verified = page.Verified
	for i := range page.Records {
		rec := &page.Records[i]
		args := string(rec.Arguments)
		if len(args) > auditArgumentsShown {
			args = strings.ToValidUTF8(args[:auditArgumentsShown], "") + " …"
		}
		v := recordView{
			Seq: rec.Seq, Time: rec.Time.UTC().Format("2006-01-02 15:04:05"), Event: rec.Event, Client: rec.Client, Tool: rec.Tool,
			Decision: rec.Decision, Approver: rec.Approver, Result: rec.Result, Arguments: args,
		}
		if rec.DurationMS > 0 {
			v.MS = strconv.FormatInt(rec.DurationMS, 10) + " ms"
		}
		view.Records = append(view.Records, v)
	}
	if n := len(page.Records); n == auditPageSize && page.Records[n-1].Seq > 1 {
		view.Older = page.Records[n-1].Seq
	}
	c.write(w, r, auditPage, view)
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

func (c *Consent) setHalt(w http.ResponseWriter, r *http.Request) {
	userID, ok := c.checked(w, r)
	if !ok {
		return
	}
	engage := r.PostForm.Get("action") == "engage"
	if err := c.halt.Set(r.Context(), engage, userID); err != nil {
		c.logger.ErrorContext(r.Context(), "kill switch", slog.Any("error", err))
		c.render(w, r, "The kill switch reported a problem: "+err.Error())
		return
	}
	if engage {
		c.render(w, r, "Halted. No tool runs until you release the kill switch.")
		return
	}
	c.render(w, r, "Released. Tools run again.")
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
<p><a href="./">Reload</a> · <a href="audit">Audit log</a></p>
{{if .Message}}<p class="msg">{{.Message}}</p>{{end}}
<section><h2>Kill switch</h2>
{{if .Halted}}<p class="warn"><strong>ha-airlock is halted.</strong> Every tool call is refused.</p>
<form method="post" action="halt"><input type="hidden" name="csrf" value="{{.CSRF}}"><button name="action" value="release">Release</button></form>
{{else}}<p>Tools run for approved applications, as the policy allows.</p>
<form method="post" action="halt"><input type="hidden" name="csrf" value="{{.CSRF}}"><button name="action" value="engage">Halt all tool calls</button></form>{{end}}
</section>
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

var auditPage = template.Must(template.New("audit").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ha-airlock — audit log</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem auto;padding:0 1rem;line-height:1.4;max-width:80rem}
table{border-collapse:collapse;width:100%}th,td{text-align:left;vertical-align:top;padding:.3rem .6rem;border-bottom:1px solid #ccc}
td{overflow-wrap:anywhere}code{font-size:.85rem}.warn{color:#a40000}.ok{color:#1a6b1a}small{color:#555}</style></head><body>
<h1>Audit log</h1>
<p><a href="./">Back</a> · <a href="audit">Newest</a></p>
{{if .Broken}}<p class="warn"><strong>The audit log is not intact.</strong> {{.Broken}}. The records below are the ones before the break.</p>
{{else}}<p class="ok">The chain holds for all {{.Verified}} records, and the file ends with the last line this server wrote.</p>{{end}}
<p><small>Times are UTC. Arguments are shown as recorded, after redaction, and shortened here; the file holds them in full.</small></p>
<table><thead><tr><th>#</th><th>Time</th><th>Event</th><th>Application</th><th>Tool</th><th>Decision</th><th>Result</th></tr></thead><tbody>
{{range .Records}}<tr><td>{{.Seq}}</td><td>{{.Time}}</td><td>{{.Event}}</td><td>{{.Client}}{{if .Approver}}<br><small>by {{.Approver}}</small>{{end}}</td>
<td>{{.Tool}}{{if .Arguments}}<br><code>{{.Arguments}}</code>{{end}}</td><td>{{.Decision}}</td><td>{{.Result}}{{if .MS}}<br><small>{{.MS}}</small>{{end}}</td></tr>
{{else}}<tr><td colspan="7">{{if .Paged}}No older record.{{else}}Nothing is recorded yet.{{end}}</td></tr>{{end}}
</tbody></table>
{{if .Older}}<p><a href="audit?before={{.Older}}">Older records</a></p>{{end}}
</body></html>`))
