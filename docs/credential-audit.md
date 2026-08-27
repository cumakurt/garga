# Credential audit

`garga auth-audit` is an isolated, opt-in credential audit. It is not the normal scan path and
it does not run unless the operator invokes this command with an explicit stdin list.

## Safety controls

- Every attempt is `GET /_security/_authenticate` (`capability.PathAuthenticate`). No write or
  state-changing request is sent. `GET /_security/user/_authenticate` is Get User and is not used.
- Default rate is 1 request/second globally and per host. Scanner `GARGA_RATE` values do not apply.
- Default per-host attempt ceiling is 5. `--max-attempts` may raise this only to 20.
- Transient retries (429/5xx/timeouts) count against the attempt ceiling and wait for the rate limiter.
- 401/403 responses are never retried for the same credential.
- The run stops on the first valid credential, when the security API is unavailable, when the
  ceiling is reached, or when the context is cancelled.

The `scan` command has no call path to this engine.

## Input

```text
garga auth-audit TARGET --credentials-stdin
```

Stdin lines:

```text
basic USERNAME PASSWORD
api_key KEY
```

The password is the remainder of the line after the username, so it may contain spaces. Blank
lines and `#` comments are ignored. At most 32 credentials are accepted, and the list is fully
parsed before any request is sent. There is no `--password` flag.

## Output

Each attempt emits one secret-free event, then a stop summary:

```text
auth-audit: attempt=1 host=192.0.2.10 username=alice outcome=invalid mechanism=basic status=401
auth-audit: attempt=2 host=192.0.2.10 username=bob outcome=valid mechanism=basic status=200
auth-audit: stopped reason=success attempts=2
```

Stop reasons are `success`, `completed`, `attempt_ceiling`, `security_unavailable`, and `canceled`.
Passwords, API keys, and Authorization headers are never copied into events, errors, or logs.
Basic Auth usernames are identities, not secrets, and may appear so the operator can tell which
entry succeeded.
