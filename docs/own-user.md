# ha-airlock's own Home Assistant user

ha-airlock acts in Home Assistant as a user of its own, so that Home
Assistant's records show what ha-airlock did
([ADR 0003](adr/0003-a-dedicated-core-user-reached-directly.md)). The App
creates that user itself.

## What happens on the first start

1. Through the Supervisor's proxy, the App asks Core for the list of users.
   If a user with the username `ha-airlock` exists, it stops here.
2. It creates the user `ha-airlock`: an administrator who may log in from
   local networks only.
3. It gives the user a random password of 32 bytes.
4. It logs in as that user once, directly at Core, and receives a refresh
   token.
5. It writes the user's id, the refresh token and the client id to
   `/data/core-credential.json`, readable by its owner only. The password
   is not written anywhere.
6. It appends a `provisioning` record to the audit log at
   `/data/audit.jsonl` — the first record of that log.
7. As the new user, it writes a logbook entry and creates a notification
   in Home Assistant saying that the user was created.

If a step after 2 fails, the App deletes the user it just created and
records the failure in the audit log.

## What happens on every later start

The App reads the credential and asks Core for an access token with it.
It does not use the proxy and creates nothing.

## When the App stops instead

- **A user `ha-airlock` exists and no credential is stored.** The App did
  not create that user, or its data was removed. It never takes a user
  over. Delete the user in Home Assistant, then start the App again.
- **Core refuses the stored credential**, for example because the refresh
  token was revoked. Delete the user in Home Assistant and the file
  `core-credential.json`, then start the App again.

## What to know

- The user is an administrator. What an MCP client may do is limited by
  ha-airlock's policy, not by Home Assistant's permissions.
- The refresh token is in the App's data directory and therefore in
  backups of the App.
- You can revoke the token at any time in Home Assistant, in the user's
  profile; ha-airlock then stops as described above.
- No MCP tool can create, change or delete a user or a token. Creating
  this one user is part of the App's start and takes no input from a
  client.
