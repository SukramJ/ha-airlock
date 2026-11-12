// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// coreAuth speaks Core's login flow and token endpoint.
type coreAuth struct {
	baseURL string
	client  *http.Client
}

func newCoreAuth(baseURL string) *coreAuth {
	return &coreAuth{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// clientID is the client ha-airlock presents itself as. Core accepts a
// client id that has the scheme and host of the request, which is how its
// own frontend logs in.
func (c *coreAuth) clientID() string { return c.baseURL + "/" }

func (c *coreAuth) webSocketURL() string {
	return "ws" + strings.TrimPrefix(c.baseURL, "http") + "/api/websocket"
}

// login runs Core's login flow with a username and password and exchanges
// the resulting code for a refresh token.
func (c *coreAuth) login(ctx context.Context, username, password string) (Credential, error) {
	start := struct {
		ClientID    string     `json:"client_id"`
		Handler     [2]*string `json:"handler"`
		RedirectURI string     `json:"redirect_uri"`
	}{ClientID: c.clientID(), RedirectURI: c.clientID()}
	provider := "homeassistant"
	start.Handler[0] = &provider

	var step struct {
		Type   string `json:"type"`
		FlowID string `json:"flow_id"`
		Result string `json:"result"`
	}
	if err := c.postJSON(ctx, "/auth/login_flow", start, &step); err != nil {
		return Credential{}, fmt.Errorf("provision: start login: %w", err)
	}
	if step.Type != "form" || step.FlowID == "" {
		return Credential{}, fmt.Errorf("provision: start login: home assistant answered with step type %q", step.Type)
	}

	submit := struct {
		Username string `json:"username"`
		Password string `json:"password"`
		ClientID string `json:"client_id"`
	}{Username: username, Password: password, ClientID: c.clientID()}
	if err := c.postJSON(ctx, "/auth/login_flow/"+url.PathEscape(step.FlowID), submit, &step); err != nil {
		return Credential{}, fmt.Errorf("provision: log in: %w", err)
	}
	if step.Type != "create_entry" || step.Result == "" {
		return Credential{}, fmt.Errorf("provision: log in: home assistant did not accept the login (step type %q)", step.Type)
	}

	tokens, err := c.token(ctx, url.Values{
		"grant_type": {"authorization_code"},
		"code":       {step.Result},
		"client_id":  {c.clientID()},
	})
	if err != nil {
		return Credential{}, fmt.Errorf("provision: exchange login code: %w", err)
	}
	if tokens.RefreshToken == "" {
		return Credential{}, errors.New("provision: exchange login code: home assistant returned no refresh token")
	}
	return Credential{RefreshToken: tokens.RefreshToken, ClientID: c.clientID()}, nil
}

// accessToken obtains a short-lived access token for a stored credential.
func (c *coreAuth) accessToken(ctx context.Context, cred Credential) (string, error) {
	tokens, err := c.token(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {cred.RefreshToken},
		"client_id":     {cred.ClientID},
	})
	var refused *statusError
	if errors.As(err, &refused) && refused.status >= 400 && refused.status < 500 {
		return "", fmt.Errorf("%w (status %d)", ErrCredentialRefused, refused.status)
	}
	if err != nil {
		return "", fmt.Errorf("refresh access token: %w", err)
	}
	if tokens.AccessToken == "" {
		return "", errors.New("refresh access token: home assistant returned no access token")
	}
	return tokens.AccessToken, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// statusError is an HTTP answer with a status other than 200. It carries
// the status only: the body of a failed auth request is not repeated.
type statusError struct{ status int }

func (e *statusError) Error() string {
	return fmt.Sprintf("home assistant answered with status %d", e.status)
}

func (c *coreAuth) token(ctx context.Context, form url.Values) (tokenResponse, error) {
	var out tokenResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/auth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return out, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := c.do(req, &out); err != nil {
		return tokenResponse{}, err
	}
	return out, nil
}

func (c *coreAuth) postJSON(ctx context.Context, path string, body, out any) error { //nolint:revive // body and out are endpoint-specific JSON: any is the encoding/json contract
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

func (c *coreAuth) do(req *http.Request, out any) error { //nolint:revive // out is endpoint-specific JSON: any is the encoding/json contract
	resp, err := c.client.Do(req)
	if err != nil {
		// The URL of a request can carry a flow id; report the cause only.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return &statusError{status: resp.StatusCode}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode answer: %w", err)
	}
	return nil
}
