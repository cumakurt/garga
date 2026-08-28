# Credential detection

`garga auth-detect` is an isolated, opt-in credential detection assessment. It is not the normal
scan path and does not run unless the operator invokes this command with an explicit mode and
an explicit username/password source.

Use it only against Elasticsearch clusters you own or are authorized to assess.

## Modes

| Mode | Technique | Attempt order | Input |
|---|---|---|---|
| `stuffing` | Credential stuffing | Operator pair order | `--credentials-stdin` or `--credentials-file` |
| `spraying` | Password spraying | Each password across every username, then the next password | `--spray-input-stdin`, or `--users-file` plus `--passwords-file` / `--passwords-stdin` |
| `brute-force` | Brute force | Many candidates against one username | `--username` with `--passwords-stdin`, `--passwords-file`, or bounded `--charset` |
| `dictionary` | Dictionary attack | Wordlist order against one username | `--username` with `--wordlist` or `--passwords-stdin` |

Spraying tries each password across every username before moving to the next password so one
account is not hit with consecutive failures. Brute-force may generate a bounded charset product
(`digits`, `lower`, `upper`, `alnum`, or a custom alphabet). Dictionary mode never generates
candidates; it only tries an operator-supplied wordlist.

## Safety controls

- Every attempt is `GET /_security/_authenticate` (`capability.PathAuthenticate`). No write or
  state-changing request is sent.
- Default rate is 1 request/second globally and per host. Scanner `GARGA_RATE` values do not apply.
- Default per-host attempt ceiling is 100. `--max-attempts` may raise this only to 1000.
- Transient retries (429/5xx/timeouts) count against the attempt ceiling and wait for the rate limiter.
- Exhausted HTTP 429 responses stop the run with reason `rate_limited`.
- 401/403 responses are never retried for the same credential.
- The run stops on the first valid credential unless `--no-stop-on-success` is set.
- Input ceilings: 512 stuffing pairs, 256 usernames, 256 passwords, 512 spraying combinations.
- Charset generation is rejected unless the cartesian product is at most 256 candidates and the
  maximum length is at most 4.
- There is no `--password` flag. List file paths may appear in process listings; file contents
  are not copied into logs, events, or errors.
- `--spray-delay` adds an extra pause after each spraying password round (maximum 5 minutes).

The `scan` command has no call path to this engine.

## Examples

Credential stuffing from a leak-style list:

```text
garga auth-detect https://es.example:9200 --mode stuffing --credentials-stdin <<'EOF'
basic elastic changeme
admin:admin123
alice,Winter2026!
bob password
EOF
```

Password spraying from username and password files:

```text
garga auth-detect https://es.example:9200 --mode spraying \
  --users-file users.txt --passwords-file passwords.txt --spray-delay 5s
```

Brute force with a bounded charset:

```text
garga auth-detect https://es.example:9200 --mode brute-force \
  --username elastic --charset digits --min-length 1 --max-length 2 --max-attempts 110
```

Dictionary attack from a wordlist file:

```text
garga auth-detect https://es.example:9200 --mode dictionary \
  --username elastic --wordlist wordlist.txt
```

## Output

Each attempt emits one secret-free event, then a stop summary. Valid Basic Auth identities may
appear so the operator can tell which account was accepted. Passwords never appear.

```text
auth-detect: mode=spraying attempt=1 host=192.0.2.10 username=elastic outcome=invalid mechanism=basic status=401
auth-detect: mode=spraying attempt=2 host=192.0.2.10 username=admin outcome=valid mechanism=basic status=200
auth-detect: mode=spraying stopped reason=success attempts=2 planned=4 valid=1 usernames=admin
```

Stop reasons are `success`, `completed`, `attempt_ceiling`, `security_unavailable`,
`rate_limited`, and `canceled`.
