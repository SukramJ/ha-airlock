// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/SukramJ/ha-airlock/internal/approval"
	"github.com/SukramJ/ha-airlock/internal/audit"
	"github.com/SukramJ/ha-airlock/internal/build"
	"github.com/SukramJ/ha-airlock/internal/catalog"
	"github.com/SukramJ/ha-airlock/internal/changes"
	"github.com/SukramJ/ha-airlock/internal/gate"
	"github.com/SukramJ/ha-airlock/internal/halt"
	"github.com/SukramJ/ha-airlock/internal/mcpserver"
	"github.com/SukramJ/ha-airlock/internal/oauth"
	"github.com/SukramJ/ha-airlock/internal/policy"
	"github.com/SukramJ/ha-airlock/internal/provision"
	"github.com/SukramJ/ha-airlock/internal/supervisor"
)

// toolTimeout bounds one tool's work in Home Assistant.
const toolTimeout = 30 * time.Second

// sweepEvery is how often expired approvals are looked for.
const sweepEvery = 20 * time.Second

// approvalNoticeID is the one notification ha-airlock keeps in Home
// Assistant while an approval is waiting.
const approvalNoticeID = "ha_airlock_approval"

// entityStates reads entity states for the approval page.
type entityStates struct{ core catalog.Core }

// States returns the state of each named entity that has one. Core has no
// command for single states over the WebSocket API, so all are read and
// the named ones kept.
func (e entityStates) States(ctx context.Context, ids []string) (map[string]string, error) {
	var all []struct {
		EntityID string `json:"entity_id"`
		State    string `json:"state"`
	}
	if err := e.core.Call(ctx, "get_states", nil, &all); err != nil {
		return nil, fmt.Errorf("get_states: %w", err)
	}
	out := make(map[string]string, len(ids))
	for i := range all {
		if slices.Contains(ids, all[i].EntityID) {
			out[all[i].EntityID] = all[i].State
		}
	}
	return out, nil
}

// changeLog is the journal of changes as the sidebar page uses it: the
// list comes from the journal, and an undo goes through the gate.
type changeLog struct {
	journal *changes.Journal
	gate    *gate.Gate
}

func (c changeLog) List() []changes.Change { return c.journal.List() }

func (c changeLog) Undo(ctx context.Context, id, by string) error { return c.gate.Undo(ctx, id, by) }

// approvalNotice returns what tells the owner, in Home Assistant, that an
// approval is waiting, and takes the notice away when none is. The notice
// names neither the action nor the application, and carries no button: an
// approval is given in the ha-airlock page and nowhere else.
func approvalNotice(core catalog.Core, logger *slog.Logger) approval.Notify {
	type call struct {
		Domain      string            `json:"domain"`
		Service     string            `json:"service"`
		ServiceData map[string]string `json:"service_data"`
	}
	return func(ctx context.Context, waiting bool) {
		// The notice is sent even if the request that caused it has ended.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		c := call{Domain: "persistent_notification", Service: "dismiss", ServiceData: map[string]string{"notification_id": approvalNoticeID}}
		if waiting {
			c.Service = "create"
			c.ServiceData["title"] = "ha-airlock"
			c.ServiceData["message"] = "An action is waiting for your approval. Open ha-airlock in Home Assistant to see it."
		}
		var answer json.RawMessage
		if err := core.Call(ctx, "call_service", c, &answer); err != nil {
			// Without the notice the request still waits in the page.
			logger.WarnContext(ctx, "the approval notice could not be updated in home assistant",
				slog.Bool("waiting", waiting), slog.Any("error", err))
		}
	}
}

// options are what the owner sets in the App's configuration.
type options struct {
	// PublicURL is the HTTPS address under which the owner's reverse proxy
	// serves ha-airlock.
	PublicURL string `json:"public_url"`
}

// loadOptions reads the options file the Supervisor writes. An App that
// was never configured has none.
func loadOptions(path string) (options, error) {
	var opts options
	data, err := os.ReadFile(path) //nolint:gosec // a fixed file in the App's data directory
	if errors.Is(err, os.ErrNotExist) {
		return opts, nil
	}
	if err != nil {
		return opts, fmt.Errorf("read options: %w", err)
	}
	if err := json.Unmarshal(data, &opts); err != nil {
		return opts, fmt.Errorf("read options: %w", err)
	}
	opts.PublicURL = strings.TrimRight(strings.TrimSpace(opts.PublicURL), "/")
	return opts, nil
}

// publicHost returns the host of a usable public URL: HTTPS, no path, no
// query. Anything else gives an error that says what is wrong.
func publicHost(publicURL string) (string, error) {
	u, err := url.Parse(publicURL)
	switch {
	case publicURL == "":
		return "", errors.New("public_url is not set")
	case err != nil || u.Host == "":
		return "", errors.New("public_url is not a URL")
	case u.Scheme != "https":
		return "", errors.New("public_url must be an https URL")
	case u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil:
		return "", errors.New("public_url must be a bare origin, without path, query or user")
	}
	return u.Host, nil
}

// loadPolicy reads the owner's policy from the App's configuration folder,
// or returns the default one; written reports which. Earlier versions read
// the file from the data directory, where the owner cannot reach it. A
// file left there is not read and not ignored either: it may hold a
// stricter rule than the default, so the server does not start with it.
func loadPolicy(configDir, dataDir string) (pol policy.Policy, written bool, err error) {
	if _, err := os.Stat(filepath.Join(dataDir, "policy.json")); err == nil {
		return policy.Policy{}, false, errors.New("policy: policy.json in the data directory is no longer read; " +
			"move it to the App's configuration folder, or remove it")
	}
	data, err := os.ReadFile(filepath.Join(configDir, "policy.json")) //nolint:gosec // a fixed file in the App's configuration folder
	if errors.Is(err, os.ErrNotExist) {
		return policy.Default(), false, nil
	}
	if err != nil {
		return policy.Policy{}, false, fmt.Errorf("read policy: %w", err)
	}
	pol, err = policy.Parse(data)
	return pol, err == nil, err
}

// runServe is the server: it makes sure ha-airlock has its Home Assistant
// user, then serves the consent page to the Supervisor and, if a public URL
// is configured, the authorization server and the MCP endpoint.
func runServe(ctx context.Context, env environment, logger *slog.Logger) int {
	if env.supervisorToken == "" {
		logger.ErrorContext(ctx, "SUPERVISOR_TOKEN is not set; the server runs inside the App container")
		return exitUsage
	}
	app, err := newApp(ctx, env, logger)
	if err != nil {
		logger.ErrorContext(ctx, "cannot start", slog.Any("error", err))
		return exitFailed
	}
	defer app.close()
	if err := app.serve(ctx, env); err != nil {
		logger.ErrorContext(ctx, "server stopped with an error", slog.Any("error", err))
		return exitFailed
	}
	return exitOK
}

// app is everything the server is made of, built in one place.
type app struct {
	logger  *slog.Logger
	audit   *audit.Log
	ingress http.Handler
	// public is nil when no usable public URL is configured.
	public http.Handler
	// sweep lets what has expired be noticed while nothing else happens.
	sweep func(context.Context)
}

func (a *app) close() { _ = a.audit.Close() }

// newApp builds the server from its parts. This is the composition root:
// the only place where the gate is given its policy and its audit log, and
// the only place where a handler is given a listener's trust.
func newApp(ctx context.Context, env environment, logger *slog.Logger) (*app, error) {
	coreURL, err := supervisor.CoreURL(ctx, env.supervisorURL, env.supervisorToken, env.coreHost)
	if err != nil {
		return nil, fmt.Errorf("learn where Core listens: %w", err)
	}
	auditLog, err := audit.Open(filepath.Join(env.dataDir, "audit.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("open the audit log: %w", err)
	}
	a := &app{logger: logger, audit: auditLog}
	built := false
	defer func() {
		if !built {
			a.close()
		}
	}()

	cred, created, err := provision.Ensure(ctx, provision.Config{
		ProxyURL:        "ws" + strings.TrimPrefix(env.supervisorURL, "http") + "/core/websocket",
		SupervisorToken: env.supervisorToken,
		CoreURL:         coreURL,
		CredentialPath:  filepath.Join(env.dataDir, "core-credential.json"),
		Audit:           auditLog,
		Logger:          logger,
	})
	if err != nil {
		return nil, fmt.Errorf("provision the Home Assistant user: %w", err)
	}
	logger.InfoContext(ctx, "home assistant user is ready", slog.String("user_id", cred.UserID), slog.Bool("created", created))

	pol, written, err := loadPolicy(env.configDir, env.dataDir)
	if err != nil {
		return nil, err
	}
	logger.InfoContext(ctx, "policy is in force", slog.Bool("from_file", written))
	store, err := oauth.Open(filepath.Join(env.dataDir, "grants.json"), auditLog)
	if err != nil {
		return nil, err
	}
	killSwitch, err := halt.Open(filepath.Join(env.dataDir, "halted"), auditLog)
	if err != nil {
		return nil, err
	}
	core := provision.NewCore(coreURL, cred)
	notice := approvalNotice(core, logger)
	// Waiting requests are kept in memory only: after a restart none
	// waits, and a notice left from before would point at nothing.
	notice(ctx, false)
	approvals := approval.New(auditLog, notice, env.now)
	a.sweep = approvals.Sweep
	journal, err := changes.Open(filepath.Join(env.dataDir, "changes.json"), env.now)
	if err != nil {
		return nil, err
	}
	tools := catalog.All()
	g := gate.New(gate.Config{
		Policy: pol, Audit: auditLog, Core: core, Tools: tools,
		Timeout: toolTimeout, Halted: killSwitch.Engaged, Approvals: approvals, Journal: journal,
	})
	consent, err := oauth.NewConsent(store, killSwitch, auditLog, approvals, entityStates{core}, changeLog{journal, g}, logger)
	if err != nil {
		return nil, err
	}
	peers, err := env.supervisorPeers(ctx)
	if err != nil {
		return nil, fmt.Errorf("learn the Supervisor's address: %w", err)
	}
	ingressMux := http.NewServeMux()
	consent.Register(ingressMux)
	// The consent page believes the user headers; only the Supervisor may
	// reach it.
	a.ingress = onlyFrom(peers, ingressMux)

	opts, err := loadOptions(filepath.Join(env.dataDir, "options.json"))
	if err != nil {
		return nil, err
	}
	host, err := publicHost(opts.PublicURL)
	if err != nil {
		logger.WarnContext(ctx, "no MCP access: the public listener stays closed", slog.Any("reason", err))
		built = true
		return a, nil
	}

	authz := oauth.NewServer(store, env.clientMetadata, opts.PublicURL, logger)
	publicMux := http.NewServeMux()
	authz.Register(publicMux)
	publicMux.Handle(oauth.PathMCP,
		mcpserver.Handler(mcpserver.New(g, tools, build.Version), authz.Verifier(), authz.ResourceMetadataURL(), host))
	a.public = onlyHost(host, publicMux)
	built = true
	return a, nil
}

// serve runs the listeners until ctx ends, then shuts them down. Each
// listener has one goroutine, which ends when its server is shut down.
func (a *app) serve(ctx context.Context, env environment) error {
	type listener struct {
		name    string
		addr    string
		handler http.Handler
	}
	listeners := []listener{{"ingress", env.ingressAddr, a.ingress}}
	if a.public != nil {
		listeners = append(listeners, listener{"public", env.publicAddr, a.public})
	}

	var (
		servers []*http.Server
		addrs   = map[string]net.Addr{}
		wg      sync.WaitGroup
		errs    = make(chan error, len(listeners))
	)
	for _, l := range listeners {
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", l.addr)
		if err != nil {
			for _, s := range servers {
				_ = s.Close()
			}
			return fmt.Errorf("listen for %s on %s: %w", l.name, l.addr, err)
		}
		srv := &http.Server{Handler: l.handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
		servers = append(servers, srv)
		addrs[l.name] = ln.Addr()
		a.logger.InfoContext(ctx, "listening", slog.String("listener", l.name), slog.String("address", ln.Addr().String()))
		wg.Go(func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errs <- fmt.Errorf("%s listener: %w", l.name, err)
			}
		})
	}
	if env.onListening != nil {
		env.onListening(addrs)
	}
	// The sweeper ends with ctx.
	wg.Go(func() {
		ticker := time.NewTicker(env.sweepEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.sweep(ctx)
			}
		}
	})

	var failure error
	select {
	case <-ctx.Done():
	case failure = <-errs:
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdownCtx)
	}
	wg.Wait()
	return failure
}

// onlyFrom lets a request through only if it comes from one of the given
// addresses.
func onlyFrom(allowed []netip.Addr, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addrPort, err := netip.ParseAddrPort(r.RemoteAddr)
		if err == nil {
			peer := addrPort.Addr().Unmap()
			for _, a := range allowed {
				if a == peer {
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		http.Error(w, "This address is served to the Home Assistant Supervisor only.", http.StatusForbidden)
	})
}

// onlyHost lets a request through only if it names the configured public
// host. A browser that was led to this port under another name — DNS
// rebinding — is turned away, and so is a proxy that does not pass the
// Host header on.
func onlyHost(host string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Host, host) {
			http.Error(w, "This server answers under its configured public address only.", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// lookupSupervisor resolves the Supervisor's addresses on the App network.
func lookupSupervisor(ctx context.Context, name string) ([]netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", name)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", name, err)
	}
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %s: no address", name)
	}
	return addrs, nil
}
