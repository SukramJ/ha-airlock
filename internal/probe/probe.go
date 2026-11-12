// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

// Package probe measures, from inside the App container, which ways to Home
// Assistant Core are open: through the Supervisor's proxy and directly, and
// as which Home Assistant user the proxy acts. It only reads, and it sends
// the Supervisor token to the Supervisor alone.
package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/SukramJ/ha-airlock/internal/hacore"
)

// Outcome is the verdict on one check.
type Outcome string

const (
	// OutcomeOK means the endpoint answered with the status the check expects.
	OutcomeOK Outcome = "ok"
	// OutcomeUnexpected means the endpoint answered, with another status.
	OutcomeUnexpected Outcome = "unexpected"
	// OutcomeUnreachable means no HTTP answer was received at all.
	OutcomeUnreachable Outcome = "unreachable"
	// OutcomeNotPerformable means an input the check needs was not obtained,
	// so the check was not run rather than run on a guessed value.
	OutcomeNotPerformable Outcome = "not performable"
)

// Names of the checks, in the order Run performs them.
const (
	CheckCoreInfo      = "supervisor: core info"
	CheckCoreProxy     = "core through the supervisor proxy"
	CheckProxyIdentity = "identity through the supervisor proxy"
	CheckCoreDirect    = "core directly, without a credential"
)

// Result is what one check found.
type Result struct {
	Check   string
	Outcome Outcome
	// Status is the HTTP status received, 0 when there was none.
	Status int
	Detail string
}

// Report is the outcome of a probe run.
type Report struct {
	Results []Result
}

// OK reports whether every check ended with OutcomeOK.
func (r Report) OK() bool {
	for _, res := range r.Results {
		if res.Outcome != OutcomeOK {
			return false
		}
	}
	return len(r.Results) > 0
}

// Config is what a Prober needs to know about its surroundings.
type Config struct {
	// SupervisorURL is the base URL of the Supervisor API, without a
	// trailing slash.
	SupervisorURL string
	// SupervisorToken is the token the Supervisor issued to this App.
	SupervisorToken string
	// CoreHost is the name under which Core is reached directly. The port
	// and the scheme are not configured; they are read from the Supervisor.
	CoreHost string
	// Timeout bounds each single request.
	Timeout time.Duration
	Logger  *slog.Logger
}

// Prober runs the checks.
type Prober struct {
	cfg    Config
	client *http.Client
}

// New returns a Prober. Redirects are not followed, so every status reported
// is the one the probed endpoint itself gave.
func New(cfg Config) *Prober {
	return &Prober{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// coreInfo is the part of the Supervisor's /core/info answer the probe uses.
type coreInfo struct {
	Result string `json:"result"`
	Data   struct {
		Port int  `json:"port"`
		SSL  bool `json:"ssl"`
	} `json:"data"`
}

// Run performs every check and logs each result.
func (p *Prober) Run(ctx context.Context) Report {
	var report Report
	add := func(res Result) {
		report.Results = append(report.Results, res)
		p.cfg.Logger.InfoContext(ctx, "probe",
			slog.String("check", res.Check),
			slog.String("outcome", string(res.Outcome)),
			slog.Int("status", res.Status),
			slog.String("detail", res.Detail),
		)
	}

	info, infoResult := p.coreInfo(ctx)
	add(infoResult)

	add(p.expectStatus(ctx, CheckCoreProxy,
		p.cfg.SupervisorURL+"/core/api/config", p.cfg.SupervisorToken, http.StatusOK))

	add(p.proxyIdentity(ctx))

	if infoResult.Outcome != OutcomeOK {
		add(Result{
			Check:   CheckCoreDirect,
			Outcome: OutcomeNotPerformable,
			Detail:  "Core's port and scheme were not obtained from the Supervisor",
		})
		return report
	}

	scheme := "http"
	if info.Data.SSL {
		scheme = "https"
	}
	direct := scheme + "://" + net.JoinHostPort(p.cfg.CoreHost, strconv.Itoa(info.Data.Port)) + "/api/"
	// No credential on purpose: Core answering 401 proves both that the
	// container reaches it and that it is Core's own auth that answers.
	add(p.expectStatus(ctx, CheckCoreDirect, direct, "", http.StatusUnauthorized))

	return report
}

// coreInfo asks the Supervisor where Core listens.
func (p *Prober) coreInfo(ctx context.Context) (coreInfo, Result) {
	var info coreInfo
	res := Result{Check: CheckCoreInfo}

	body, status, err := p.get(ctx, p.cfg.SupervisorURL+"/core/info", p.cfg.SupervisorToken)
	res.Status = status
	if err != nil {
		res.Outcome = OutcomeUnreachable
		res.Detail = err.Error()
		return info, res
	}
	if status != http.StatusOK {
		res.Outcome = OutcomeUnexpected
		res.Detail = "expected status 200"
		return info, res
	}
	if err := json.Unmarshal(body, &info); err != nil {
		res.Outcome = OutcomeUnexpected
		res.Detail = fmt.Sprintf("answer is not the expected JSON: %v", err)
		return info, res
	}
	if info.Result != "ok" || info.Data.Port == 0 {
		res.Outcome = OutcomeUnexpected
		res.Detail = "answer carries no result ok with a port"
		return info, res
	}
	res.Outcome = OutcomeOK
	res.Detail = fmt.Sprintf("port %d, ssl %t", info.Data.Port, info.Data.SSL)
	return info, res
}

// proxyIdentity asks Core, over the proxy's WebSocket, which user the
// connection acts as. It reports what Core says and expects no particular
// name.
func (p *Prober) proxyIdentity(ctx context.Context) Result {
	res := Result{Check: CheckProxyIdentity}
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()

	// The proxy's WebSocket lives beside its HTTP API, under the ws scheme.
	url := "ws" + strings.TrimPrefix(p.cfg.SupervisorURL, "http") + "/core/websocket"
	conn, err := hacore.Dial(ctx, url, p.cfg.SupervisorToken)
	if err != nil {
		res.Outcome = OutcomeUnreachable
		if errors.Is(err, hacore.ErrAuthInvalid) {
			res.Outcome = OutcomeUnexpected
		}
		res.Detail = err.Error()
		return res
	}
	defer func() { _ = conn.Close() }()

	var user struct {
		Name    string `json:"name"`
		IsAdmin bool   `json:"is_admin"`
		IsOwner bool   `json:"is_owner"`
	}
	if err := conn.Call(ctx, "auth/current_user", nil, &user); err != nil {
		res.Outcome = OutcomeUnexpected
		res.Detail = err.Error()
		return res
	}
	res.Outcome = OutcomeOK
	res.Detail = fmt.Sprintf("user %q, admin %t, owner %t", user.Name, user.IsAdmin, user.IsOwner)
	return res
}

// expectStatus requests url and compares the status with want.
func (p *Prober) expectStatus(ctx context.Context, check, url, token string, want int) Result {
	res := Result{Check: check}
	_, status, err := p.get(ctx, url, token)
	res.Status = status
	switch {
	case err != nil:
		res.Outcome = OutcomeUnreachable
		res.Detail = err.Error()
	case status != want:
		res.Outcome = OutcomeUnexpected
		res.Detail = fmt.Sprintf("expected status %d", want)
	default:
		res.Outcome = OutcomeOK
	}
	return res
}

// maxBody bounds how much of an answer is read; the probe needs a few
// fields of one small document.
const maxBody = 1 << 20

// get performs one GET. An empty token sends no Authorization header.
func (p *Prober) get(ctx context.Context, url, token string) (body []byte, status int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err = io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read answer: %w", err)
	}
	return body, resp.StatusCode, nil
}
