# ADR 0004 — The authorization server lives in the App; consent is given in the Ingress UI

Status: accepted, 2026-11-12 (owner decision). Not implemented yet.

## Context

Owner decisions of 2026-11-12: MCP clients authenticate with OAuth 2.1 from
the first networked version on; the server is reached through a port that
is closed after installation; HTTPS comes from the owner's reverse proxy.

What the MCP specification, revision 2026-07-28, requires
(<https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization>
and its pages *security-considerations* and *client-registration*, read on
2026-11-12):

- The MCP server is an OAuth 2.1 resource server. It MUST serve Protected
  Resource Metadata (RFC 9728), MUST validate that a token was issued for
  it, and MUST answer an invalid token with 401.
- "All authorization server endpoints MUST be served over HTTPS", and "all
  redirect URIs MUST be either `localhost` or use HTTPS".
- Clients MUST use PKCE and MUST refuse a server whose metadata lacks
  `code_challenge_methods_supported`. Clients MUST send the `resource`
  parameter (RFC 8707).
- Authorization servers SHOULD support Client ID Metadata Documents;
  Dynamic Client Registration is deprecated. With metadata documents the
  server MUST check that the document's `client_id` equals its URL, MUST
  validate the redirect URI against the document, and MUST display the
  redirect URI's hostname during authorization.
- For public clients the authorization server MUST rotate refresh tokens.
- Authorization servers SHOULD send `iss` in the authorization response
  (RFC 9207).

What the SDK provides (`modelcontextprotocol/go-sdk` at `328036e`): the
resource-server side — bearer-token middleware (`auth/auth.go:97`) and the
metadata handler (`auth/auth.go:197`). It contains no authorization server.

What Home Assistant provides: for a request through Ingress the Supervisor
names the Home Assistant user itself (`supervisor/api/ingress.py:400-418`,
Supervisor `98a2322`).

Home Assistant's own login was considered as the authorization server and
rejected: the client would then hold a token that Core accepts directly,
and could act around ha-airlock.

## Decision

**One listener, behind the owner's proxy.** The App serves plain HTTP on
one port that is not published after installation. The owner publishes it
and points a hostname of their reverse proxy at it. The App option
`public_url` holds that HTTPS URL; it is the issuer, and `public_url` +
`/mcp` is the resource. Without `public_url`, or with one that is not
HTTPS, the listener does not start. A request whose `Host` is not the host
of `public_url` is refused.

**The authorization server is part of the App.** It serves its metadata
(RFC 8414), an authorization endpoint and a token endpoint, and nothing
else: authorization code with PKCE `S256` only, no implicit grant, no
client secrets. A code is single-use, bound to client, redirect URI,
challenge and resource, and expires after one minute. The `resource` must
be this server's. Responses carry `iss`.

**Clients identify themselves with a Client ID Metadata Document.** The
App fetches the document over HTTPS from a public address only — no
private, loopback or link-local address, no redirects, a size and a time
limit — so that the fetch cannot be turned against the home network. No
Dynamic Client Registration.

**The authorization endpoint authenticates nobody.** It parks the request,
shows a short code, and asks the owner to open ha-airlock in Home
Assistant. There, in the Ingress UI, the Supervisor names the user, who
must be an administrator. The UI shows the client's name, the host of its
client id, the host of its redirect URI and the code; the owner compares
the code, picks the profile the client gets, and approves or refuses. Only
then does the waiting browser tab receive the redirect with the
authorization code. A parked request expires after ten minutes.

**Tokens are random, opaque and stored as hashes.** Access tokens live
fifteen minutes; refresh tokens rotate on every use, and a reused one
revokes the whole grant. Each grant belongs to one client and one profile
and is listed, and revocable, in the Ingress UI. Every issue, refusal and
revocation is an audit record.

**The profile belongs to the grant, not to the network.** Behind a proxy
every client arrives from the same address, so "local" and "remote" stop
being properties the server can observe. They become two named profiles
the owner assigns at approval.

## Consequences

- The App gains its largest security-critical part: an authorization
  server of roughly the size of everything built so far.
- The Ingress UI becomes a precondition of the first usable version, not a
  later convenience.
- ha-airlock makes outbound HTTPS requests to addresses a client chooses.
- A client that only supports Dynamic Client Registration cannot connect.
- Without the owner's reverse proxy there is no MCP access at all.
- `CONCEPT.md` §3 and §5 change: the listener is not bound to loopback,
  and the two profiles are assigned, not derived from the listener.

## Better than others, better than before, the right cut

**Better than the comparison targets?** ha-mcp signs Home Assistant's
long-lived token into its OAuth token and trusts the client. Core's
`mcp_server` hands the client a Home Assistant token. Here the client never
holds anything Core accepts, and consent is given by an administrator whom
the Supervisor identified, not by whoever reached a login form.

**Better than before?** The concept said "OAuth 2.1 with PKCE" without
saying who the authorization server is. This says it, and binds approval
of a client to the same out-of-band channel as approval of an action
(ADR 0002).

**Is the cut right?** It is the owner's decision to build it now. The
assistant's recommendation was a per-client token with only its hash
stored for phase 1, and the authorization server with the remote listener
in phase 5: the tool chain could then have been reviewed without it. The
cut inside the App is right either way — the resource server uses the
SDK, the authorization server is one package with no knowledge of tools,
and the consent screen is one more page of the UI that approves actions.

## Known weakness

Approval by code comparison can be phished: an attacker starts an
authorization and persuades the owner to approve it. The Ingress UI
therefore shows where the request came from and what it will be allowed,
and a parked request is short-lived; it does not make the owner immune.

## Measured

On the owner's instance, 2026-11-13, with Claude Code 2.1.323 as the MCP
client, behind the owner's HTTPS reverse proxy:

- Claude Code registers by a Client ID Metadata Document. Its
  authorization request carried the client id
  `https://claude.ai/oauth/claude-code-client-metadata` and a redirect URI
  `http://localhost:<port>/callback` with a port of its own choosing; the
  document lists `http://localhost/callback` and
  `http://127.0.0.1/callback`. The loopback rule of `MatchRedirect`
  (`internal/oauth/clientmeta.go`) is what lets the two meet.
- The sign-in was started with `claude mcp login`, the owner approved it
  in the sidebar page, and the client then reported the server as
  connected and listed all thirteen tools. The authorization endpoint that
  waits for an approval given elsewhere was accepted by this client.
- Without a token, a request to the MCP address through the proxy was
  answered 401 with the `resource_metadata` pointer; a request to the port
  under another host name was answered 421.

## Unverified

- Which registration mechanism MCP clients other than Claude Code support.
- That clients other than Claude Code accept an authorization endpoint
  that waits for an approval given in another tab.
- OAuth 2.1 itself (`draft-ietf-oauth-v2-1-13`) was not read for this ADR;
  only the MCP pages that refer to it. It is read before the endpoints are
  written.
- How the owner's reverse proxy is configured. The listener cannot verify
  that the connection in front of it was encrypted.
