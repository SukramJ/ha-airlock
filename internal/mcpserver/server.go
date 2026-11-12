// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

// Package mcpserver presents the tool catalogue over the Model Context
// Protocol. It contains no decision of its own: every tool call, for a
// declared tool or not, goes to the gate, and what the gate returns is what
// the client gets.
package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/SukramJ/ha-airlock/internal/catalog"
	"github.com/SukramJ/ha-airlock/internal/gate"
)

// profileKey is where a verified token carries the profile of its client.
const profileKey = "ha-airlock/profile"

// TokenInfo describes a verified access token to the server: which client
// it belongs to and which profile that client was given.
func TokenInfo(client, profile string, expiration time.Time) *auth.TokenInfo {
	return &auth.TokenInfo{
		UserID:     client,
		Expiration: expiration,
		// any is the SDK's type for transport-specific token data.
		Extra: map[string]any{profileKey: profile},
	}
}

// principalOf turns what the transport verified into the gate's caller. A
// request without a verified token has none.
func principalOf(extra *mcp.RequestExtra) *gate.Principal {
	if extra == nil || extra.TokenInfo == nil || extra.TokenInfo.UserID == "" {
		return nil
	}
	profile, _ := extra.TokenInfo.Extra[profileKey].(string)
	return &gate.Principal{Client: extra.TokenInfo.UserID, Profile: profile}
}

// New returns an MCP server offering exactly the given tools.
func New(g *gate.Gate, tools []catalog.Tool, version string) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "ha-airlock", Version: version}, nil)
	declared := make(map[string]bool, len(tools))
	for _, tool := range tools {
		declared[tool.Name] = true
		server.AddTool(&mcp.Tool{
			Name:        tool.Name,
			Title:       tool.Title,
			Description: tool.Description,
			InputSchema: tool.InputSchema,
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: tool.Tier == catalog.R0},
		}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return callGate(ctx, g, req.Extra, req.Params.Name, req.Params.Arguments), nil
		})
	}

	// The SDK answers a call to a tool it does not know by itself. Such a
	// call is a refusal like any other and has to reach the audit log, so it
	// is taken to the gate here, before the SDK sees it.
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "tools/call" {
				if params, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok && !declared[params.Name] {
					return callGate(ctx, g, req.GetExtra(), params.Name, params.Arguments), nil
				}
			}
			return next(ctx, method, req)
		}
	})
	return server
}

// callGate runs one call through the gate and renders the outcome.
func callGate(ctx context.Context, g *gate.Gate, extra *mcp.RequestExtra, name string, args json.RawMessage) *mcp.CallToolResult {
	outcome, err := g.Call(ctx, principalOf(extra), name, args)
	if err != nil {
		// The gate withheld the result because it could not record the call.
		return failure("The call could not be recorded in the audit log, so no result is returned.")
	}
	if outcome.Output == nil {
		return failure(outcome.Message)
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(outcome.Output)}}}
}

func failure(message string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: message}}}
}

// Handler serves the MCP server over Streamable HTTP. Every request must
// name publicHost in its Host header and carry an access token the verifier
// accepts; without a token the answer is 401 and points to
// resourceMetadataURL, as RFC 9728 describes.
func Handler(server *mcp.Server, verifier auth.TokenVerifier, resourceMetadataURL, publicHost string) http.Handler {
	streamable := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{
			Stateless:    true,
			JSONResponse: true,
			// The SDK's own protection refuses any Host that is not a
			// loopback name on a loopback connection. Here the expected Host
			// is known exactly, and is checked below for every connection.
			DisableLocalhostProtection: true,
		},
	)
	protected := auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: resourceMetadataURL,
	})(streamable)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A browser led to this port under another name — DNS rebinding —
		// is turned away before anything else is looked at.
		if !strings.EqualFold(r.Host, publicHost) {
			http.Error(w, "This server answers under its configured public address only.", http.StatusMisdirectedRequest)
			return
		}
		protected.ServeHTTP(w, r)
	})
}
