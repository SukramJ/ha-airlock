# Connecting an MCP client

ha-airlock gives an MCP client access to Home Assistant only after you
approved that client in Home Assistant. This page describes what you set
up and what happens.

So far ha-airlock offers tools that read and diagnose only; `tools.md`
lists them.

## What you need

- A reverse proxy that serves HTTPS and that you control — the one that
  already serves your Home Assistant will do.
- A hostname for ha-airlock on that proxy, for example
  `airlock.example.org`.

ha-airlock does not speak HTTPS itself, and it does not work without it:
the MCP specification requires an authorization server to be served over
HTTPS.

## Setting it up

1. In the App's **Network** settings, publish port `8443`. It is closed
   after installation.
2. Point your proxy's hostname at that port, plain HTTP. The proxy must
   pass the `Host` header on unchanged; ha-airlock answers only requests
   that name its public host.
3. In the App's **Configuration**, set `public_url` to the HTTPS origin,
   for example `https://airlock.example.org` — no path.
4. Restart the App.

Without a `public_url`, or with one that is not an HTTPS origin, the port
stays closed and the App's log says why.

The address a client connects to is `public_url` followed by `/mcp`.

## Approving a client

1. Add the MCP address to your client. It opens a browser window.
2. The window shows **Waiting for approval** and a code such as
   `K7QM-2XHD`.
3. In Home Assistant, open **ha-airlock** in the sidebar. The request is
   listed with the application's name, the host that identifies it, the
   host its answer goes to, and the code.
4. Compare the code. Choose a profile and approve, or deny.
5. The waiting window continues on its own.

Approve only a request you started yourself a moment ago. Someone else can
start a request and try to get you to approve it; the code and the hosts
shown are how you tell.

A request waits ten minutes. Only a Home Assistant administrator can open
the page.

## Profiles

A profile decides what a client may do. You assign it when you approve.

| Profile | Without a policy file |
| --- | --- |
| `local` | may read and diagnose |
| `remote` | may do nothing yet |

To change this, put a file `policy.json` into the App's data directory:

```json
{
  "version": 1,
  "profiles": {
    "local":  { "R0": "allow" },
    "remote": { "R0": "deny" }
  }
}
```

`R0` to `R4` are the risk tiers; `R0` is reading and diagnosing, and no
tool of a higher tier exists yet. Whatever the file does not allow is
denied. A file with a key, profile, tier or decision ha-airlock does not
know is rejected as a whole, and the App does not start — a misspelt rule
is not silently ignored.

## Revoking

The sidebar page lists the approved applications. **Revoke access** ends
an application's access at once.

Access also ends by itself when an application has not used it for thirty
days.

## What a client receives, and what is recorded

- Every result is wrapped with a notice that it is untrusted data from
  Home Assistant.
- Passwords, tokens, keys and coordinates are removed from results:
  values of keys with such names, and text that has the shape of a
  credential. This catches what logs and diagnostics commonly contain; it
  is not a proof that nothing sensitive is left.
- Every call — allowed, refused or failed — is a record in the audit log
  (`docs/audit-log.md`), with the client, the tool, the redacted
  arguments, the decision and a hash of the result. Approvals, denials and
  revocations are records too.
- Switching something needs more than access: see
  `docs/approving-actions.md`.
- If a call cannot be recorded, its result is not returned.

## What ha-airlock connects to on the internet

An application identifies itself by an HTTPS address at which it publishes
a small document about itself. ha-airlock fetches that document when the
application asks for access. It fetches from public addresses only, over
HTTPS, without following redirects.

An application that can only register itself dynamically (OAuth Dynamic
Client Registration) cannot connect.

## Stopping everything

The sidebar page has a kill switch. **Halt all tool calls** makes ha-airlock
refuse every tool call of every application at once, until you release it.
The state survives a restart of the App. Halting works even if it cannot be
written to the audit log; releasing does not.

## How many calls an application may make

Each approved application may make a number of tool calls per minute: 60
with the `local` profile, 30 with `remote`. Calls that are refused count
too. To change the numbers, add `limits` to `policy.json`:

```json
{
  "version": 1,
  "profiles": { "local": { "R0": "allow" } },
  "limits": { "local": { "calls_per_minute": 20 } }
}
```

## Clients this was tried with

- **Claude Code** (2.1.323): `claude mcp add --transport http ha-airlock
  https://<your address>/mcp`, then `claude mcp login ha-airlock` in a
  terminal, or `/mcp` in a session started after the server was added.
  It identifies itself with a metadata document, so nothing has to be
  registered beforehand.

No other client has been tried.

## Not there yet

- Tools that change the system or files, and most kinds of
  configuration: only toggle helpers can be changed, see
  `docs/changing-configuration.md`. What exists today is in
  `docs/tools.md`.
