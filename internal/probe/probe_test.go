// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package probe_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/SukramJ/ha-airlock/internal/hacore/hacoretest"
	"github.com/SukramJ/ha-airlock/internal/probe"
)

const testToken = "supervisor-token-for-test"

// fakeCore answers like Core does to a request without a credential, and
// records every Authorization header it was sent.
type fakeCore struct {
	server *httptest.Server
	mu     sync.Mutex
	auth   []string
}

func newFakeCore(t *testing.T) *fakeCore {
	t.Helper()
	c := &fakeCore{}
	c.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.auth = append(c.auth, r.Header.Get("Authorization"))
		c.mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(c.server.Close)
	return c
}

func (c *fakeCore) port(t *testing.T) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(c.server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split fake core address: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse fake core port: %v", err)
	}
	return port
}

// fakeSupervisor serves /core/info, the proxied /core/api/config and the
// proxied WebSocket, and refuses every request that does not carry the
// App's token.
func fakeSupervisor(t *testing.T, infoStatus, proxyStatus, corePort int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	guard := func(status int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+testToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}
	}
	mux.HandleFunc("/core/info", guard(infoStatus,
		fmt.Sprintf(`{"result":"ok","data":{"port":%d,"ssl":false}}`, corePort)))
	mux.HandleFunc("/core/api/config", guard(proxyStatus, `{}`))
	mux.Handle("/core/websocket", hacoretest.Handler(testToken, map[string]string{
		"auth/current_user": `{"id":"abc","name":"Supervisor","is_admin":true,"is_owner":false}`,
	}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func run(t *testing.T, supervisorURL string) probe.Report {
	t.Helper()
	p := probe.New(probe.Config{
		SupervisorURL:   supervisorURL,
		SupervisorToken: testToken,
		CoreHost:        "127.0.0.1",
		Timeout:         5 * time.Second,
		Logger:          slog.New(slog.DiscardHandler),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return p.Run(ctx)
}

func outcomes(r probe.Report) map[string]probe.Outcome {
	m := make(map[string]probe.Outcome, len(r.Results))
	for _, res := range r.Results {
		m[res.Check] = res.Outcome
	}
	return m
}

func TestRunReportsEveryWayOpen(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	sup := fakeSupervisor(t, http.StatusOK, http.StatusOK, core.port(t))

	report := run(t, sup.URL)

	if !report.OK() {
		t.Fatalf("report not OK: %+v", report.Results)
	}
	if len(report.Results) != 4 {
		t.Fatalf("got %d results, want 4: %+v", len(report.Results), report.Results)
	}
}

func TestRunReportsTheUserTheProxyActsAs(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	sup := fakeSupervisor(t, http.StatusOK, http.StatusOK, core.port(t))

	report := run(t, sup.URL)

	for _, res := range report.Results {
		if res.Check != probe.CheckProxyIdentity {
			continue
		}
		if res.Outcome != probe.OutcomeOK || res.Detail != `user "Supervisor", admin true, owner false` {
			t.Fatalf("identity check = %+v", res)
		}
		return
	}
	t.Fatal("no identity check in the report")
}

func TestRunNeverSendsTheSupervisorTokenToCore(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	sup := fakeSupervisor(t, http.StatusOK, http.StatusOK, core.port(t))

	run(t, sup.URL)

	core.mu.Lock()
	defer core.mu.Unlock()
	if len(core.auth) != 1 {
		t.Fatalf("fake core got %d requests, want 1", len(core.auth))
	}
	if core.auth[0] != "" {
		t.Fatalf("direct request to Core carried an Authorization header")
	}
}

func TestRunReportsCoreUnreachableWhenNothingListens(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	port := core.port(t)
	core.server.Close()
	sup := fakeSupervisor(t, http.StatusOK, http.StatusOK, port)

	report := run(t, sup.URL)

	if got := outcomes(report)[probe.CheckCoreDirect]; got != probe.OutcomeUnreachable {
		t.Fatalf("direct check = %q, want %q", got, probe.OutcomeUnreachable)
	}
	if report.OK() {
		t.Fatal("report OK although Core was unreachable")
	}
}

func TestRunDoesNotGuessCorePortWhenSupervisorRefusesInfo(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	sup := fakeSupervisor(t, http.StatusForbidden, http.StatusOK, core.port(t))

	report := run(t, sup.URL)

	got := outcomes(report)
	if got[probe.CheckCoreInfo] != probe.OutcomeUnexpected {
		t.Fatalf("info check = %q, want %q", got[probe.CheckCoreInfo], probe.OutcomeUnexpected)
	}
	if got[probe.CheckCoreDirect] != probe.OutcomeNotPerformable {
		t.Fatalf("direct check = %q, want %q", got[probe.CheckCoreDirect], probe.OutcomeNotPerformable)
	}
	core.mu.Lock()
	defer core.mu.Unlock()
	if len(core.auth) != 0 {
		t.Fatalf("Core was contacted %d times without a known port", len(core.auth))
	}
}

func TestRunReportsProxyRefusal(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	sup := fakeSupervisor(t, http.StatusOK, http.StatusUnauthorized, core.port(t))

	report := run(t, sup.URL)

	if got := outcomes(report)[probe.CheckCoreProxy]; got != probe.OutcomeUnexpected {
		t.Fatalf("proxy check = %q, want %q", got, probe.OutcomeUnexpected)
	}
}
