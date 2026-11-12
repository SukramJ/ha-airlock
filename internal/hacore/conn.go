// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

// Package hacore speaks Home Assistant Core's WebSocket API: the auth
// handshake, then commands answered one at a time.
//
// The same protocol is spoken by Core itself and by the Supervisor's proxy
// in front of it; only the URL and the token differ.
package hacore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// readLimit bounds one message from Core. A list of all states of a large
// installation is several megabytes.
const readLimit = 64 << 20

// handshakeTimeout bounds the WebSocket handshake when the context carries
// no earlier deadline.
const handshakeTimeout = 15 * time.Second

// ErrAuthInvalid reports that Core, or the proxy, refused the token.
var ErrAuthInvalid = errors.New("home assistant refused the credential")

// CommandError is the error Core returned for a command.
type CommandError struct {
	Code    string
	Message string
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("home assistant command failed: %s: %s", e.Code, e.Message)
}

// Conn is one authenticated connection. Its methods are safe for concurrent
// use; commands are sent and answered one after the other.
type Conn struct {
	mu     sync.Mutex
	ws     *websocket.Conn
	lastID uint64
}

// serverMessage is the envelope of everything Core sends.
type serverMessage struct {
	ID      uint64          `json:"id"`
	Type    string          `json:"type"`
	Success bool            `json:"success"`
	Result  json.RawMessage `json:"result"`
	Message string          `json:"message"`
	Error   *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// Dial connects to url and authenticates with token. The token is sent in
// the auth message only, never in a header or the URL.
func Dial(ctx context.Context, url, token string) (*Conn, error) {
	dialer := websocket.Dialer{HandshakeTimeout: handshakeTimeout}
	ws, resp, err := dialer.DialContext(ctx, url, nil)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("connect to home assistant: %w", err)
	}
	ws.SetReadLimit(readLimit)
	c := &Conn{ws: ws}
	if err := c.authenticate(ctx, token); err != nil {
		_ = ws.Close()
		return nil, err
	}
	return c, nil
}

func (c *Conn) authenticate(ctx context.Context, token string) error {
	release := c.bind(ctx)
	defer release()

	var msg serverMessage
	if err := c.ws.ReadJSON(&msg); err != nil {
		return fmt.Errorf("read auth request: %w", ctxErr(ctx, err))
	}
	if msg.Type != "auth_required" {
		return fmt.Errorf("home assistant opened with %q, not with an auth request", msg.Type)
	}
	auth := struct {
		Type        string `json:"type"`
		AccessToken string `json:"access_token"`
	}{Type: "auth", AccessToken: token}
	if err := c.ws.WriteJSON(auth); err != nil {
		return fmt.Errorf("send credential: %w", ctxErr(ctx, err))
	}
	if err := c.ws.ReadJSON(&msg); err != nil {
		return fmt.Errorf("read auth answer: %w", ctxErr(ctx, err))
	}
	switch msg.Type {
	case "auth_ok":
		return nil
	case "auth_invalid":
		return fmt.Errorf("%w: %s", ErrAuthInvalid, msg.Message)
	default:
		return fmt.Errorf("home assistant answered the credential with %q", msg.Type)
	}
}

// Call sends one command and decodes its result into out, which may be nil.
// params are the command's own fields and must encode as a JSON object, or
// be nil.
//
// When ctx ends during a call the connection is closed: the answer would
// otherwise arrive later and be taken for the next command's.
func (c *Conn) Call(ctx context.Context, command string, params, out any) error { //nolint:revive // params and out are command-specific JSON: any is the encoding/json contract
	c.mu.Lock()
	defer c.mu.Unlock()

	fields := map[string]json.RawMessage{}
	if params != nil {
		raw, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("encode %s: %w", command, err)
		}
		if err := json.Unmarshal(raw, &fields); err != nil {
			return fmt.Errorf("encode %s: parameters are not a JSON object: %w", command, err)
		}
	}
	// Core requires identifiers to increase over the life of a connection.
	c.lastID++
	id := c.lastID
	fields["id"] = json.RawMessage(strconv.FormatUint(id, 10))
	typ, err := json.Marshal(command)
	if err != nil {
		return fmt.Errorf("encode %s: %w", command, err)
	}
	fields["type"] = typ

	release := c.bind(ctx)
	defer release()

	if err := c.ws.WriteJSON(fields); err != nil {
		return fmt.Errorf("send %s: %w", command, ctxErr(ctx, err))
	}
	for {
		var msg serverMessage
		if err := c.ws.ReadJSON(&msg); err != nil {
			return fmt.Errorf("read answer to %s: %w", command, ctxErr(ctx, err))
		}
		// Events and anything else that is not this command's result.
		if msg.Type != "result" || msg.ID != id {
			continue
		}
		if !msg.Success {
			cmdErr := &CommandError{Code: "unknown", Message: "no error given"}
			if msg.Error != nil {
				cmdErr.Code, cmdErr.Message = msg.Error.Code, msg.Error.Message
			}
			return cmdErr
		}
		if out == nil {
			return nil
		}
		if err := json.Unmarshal(msg.Result, out); err != nil {
			return fmt.Errorf("decode result of %s: %w", command, err)
		}
		return nil
	}
}

// Close closes the connection.
func (c *Conn) Close() error {
	if err := c.ws.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("close connection to home assistant: %w", err)
	}
	return nil
}

// bind ties the connection to ctx for the time of one exchange: a deadline
// becomes the connection's deadline, and a cancellation closes it. The
// returned function ends the tie; the watcher context.AfterFunc starts runs
// at most once and only if ctx ends first.
func (c *Conn) bind(ctx context.Context) (release func()) {
	deadline, _ := ctx.Deadline()
	_ = c.ws.SetReadDeadline(deadline)
	_ = c.ws.SetWriteDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = c.ws.Close() })
	return func() { stop() }
}

// ctxErr prefers the context's error over the network error it caused.
func ctxErr(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}
