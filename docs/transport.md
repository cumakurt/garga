# HTTP transport contract

The internal transport layer owns connection reuse, TLS policy, proxy selection, timeouts,
redirect handling, bounded response consumption, and credential-safe error classification.
Higher layers provide request semantics and must reuse one factory for every compatible scan
configuration rather than creating a client per target.

## Resource and timeout policy

Each factory owns one concurrent-safe `http.Client` and one connection pool. Application scanner
settings derive the connect, overall request, response-body, and idle-pool limits. The transport
also sets independent TLS-handshake, response-header, idle-connection, and expect-continue
timeouts. Response headers default to a 64 KiB cap; response bodies use the configured cap and
are read through a limiting reader.

Bodies are always closed. A response at or below the limit is fully consumed so its connection
can be reused. An oversized response is stopped after one byte beyond the limit and its
connection is closed instead of draining an untrusted body.

## TLS and proxy policy

- TLS 1.2 is the minimum protocol version.
- Certificate and hostname verification are enabled by default.
- Explicit insecure mode disables certificate verification only; other timeouts and limits stay
  active.
- Custom root pools are cloned when a factory is created.
- The system proxy environment is honored by default. A caller may disable it or supply an
  explicit `http`, `https`, `socks5`, or `socks5h` proxy URL.

## Redirect and credential policy

Redirects have an explicit finite limit. User information in request or redirect URLs is
rejected. On a cross-origin redirect, the transport removes `Authorization`,
`Proxy-Authorization`, `Cookie`, and `Referer` before sending the next request. The configured
garga user agent is applied to every outgoing request.

## Method safety

The transport sends only `GET` and never attaches a request body. `NewRequest` and `Client.Do`
reject other methods, an empty method, and a non-nil body as `invalid_request`. Redirects that
would change the method or attach a body are rejected. Path allowlists for Elasticsearch APIs
remain in `internal/capability` and `internal/credential`; this layer enforces the HTTP method
only.

## Error contract

Transport failures use stable kinds for invalid requests, cancellation, timeout, DNS, TLS,
connect, redirect, protocol, general network, response read, and response-size failures. Their
formatted text never includes URLs, headers, proxy credentials, response content, or raw parser
input. Causes remain available through Go error unwrapping for control-flow checks.
