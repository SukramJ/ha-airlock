# The audit log

ha-airlock records what it does in one file, one JSON line per event. Each
line is tied to the line before it by a hash, so a change to the file shows
when the file is checked.

The server writes it: every tool call, refused ones included, every
approval, denial and revocation of an application, every use of the kill
switch, and the creation of ha-airlock's own Home Assistant user. In the
App the file is `/data/audit.jsonl`.

## Format

```json
{"hash":"9f2c…","entry":{"seq":2,"prev":"41ab…","time":"2026-11-12T18:00:00.123Z","event":"tool_call","client":"…","tool":"…","arguments":{},"decision":"allow"}}
```

- `entry.seq` counts the lines from 1.
- `entry.prev` is the `hash` of the line before; the first line carries 64
  zeros.
- `hash` is the SHA-256, in hex, of the bytes of `entry` exactly as they
  stand in the file.
- The other fields of `entry` describe the event: `event`, `client`,
  `tool`, `arguments`, `decision`, `approver`, `diff`, `result`,
  `duration_ms`. Empty ones are left out.

The file is created readable and writable by its owner only, and every line
is flushed to stable storage before the append returns.

An entry larger than about 4 MB encoded is refused rather than written:
the check reads lines up to that size, and a longer one would make the
whole log fail it.

## Checking a log

```sh
ha-airlock audit verify /path/to/audit.jsonl
```

prints `ok: N records, head H` and exits with status 0, or names the first
line that does not fit and exits with status 1.

The server runs the same check when it opens the log and refuses to append
to a log that fails it.

## Reading the log in Home Assistant

The ha-airlock page in Home Assistant has a link "Audit log". It shows the
records newest first, a hundred at a time, to administrators only. Times
are UTC. Arguments longer than 400 bytes are shortened on the page; the
file holds them in full.

Every time the page is opened the server checks the whole chain, and
compares the end of the file with the last line it wrote itself. So while
the server runs, the page also reports lines cut off the end of the file,
which the check of a file alone cannot. The comparison value lives in the
server's memory: it does not survive a restart, and it does not help
against someone who can change the running server.

If the log is not intact the page says so, names the place, and shows the
records before it.

## What the check shows, and what it does not

It shows that a line was changed, removed, inserted or moved, and that the
last line was written incompletely.

It does not show that whole lines were cut off the end: the shorter log is
still a valid chain. And whoever can write the file can rewrite all of it
with fresh hashes. To notice either, compare the `head` the check prints
with a value noted earlier somewhere the writer of the file cannot reach.

A crash while a line is being written leaves an incomplete last line. The
check reports it and the server does not start on that log; there is no
repair command yet.
