# Target Input Contract

This document describes the target normalization and streaming source behavior implemented by
Work Packages 1.1 and 1.2. The scanner CLI is not exposed yet, but future commands must preserve
this contract unless a documented compatibility change replaces it.

## Single targets

Accepted single-target forms:

```text
192.0.2.10
192.0.2.10:9200
example.org
example.org:9200
[2001:db8::10]
[2001:db8::10]:9200
[fe80::10%eth0]:9200
http://example.org
https://example.org:9243/elastic
https://[fe80::10%25eth0]:9200/elastic
```

Normalization rules:

- surrounding whitespace is removed;
- DNS names are lowercased and one trailing root dot is removed;
- IPv4 and IPv6 literals use their canonical textual representation;
- IPv6 ports require brackets;
- IPv6 zone identifiers allow ASCII letters, digits, `-`, `.`, `_`, and `~`;
- HTTP defaults to port 80 and HTTPS defaults to port 443;
- a URL root path is normalized to an empty base path;
- percent-escape hex digits in URL paths are uppercased;
- URL user information, query parameters, and fragments are rejected;
- single input values are limited to 8 KiB.

Bare paths are not accepted. A reverse-proxy base path must be part of an explicit HTTP(S) URL.
Internationalized DNS names must be supplied in their ASCII/Punycode form.

## Port lists

Port lists accept comma-separated decimal ports and inclusive ranges:

```text
80,443,9200-9203
```

Results are sorted and deduplicated. Valid ports are 1 through 65535. Empty entries, reversed
ranges, non-decimal values, and inputs larger than 8 KiB are rejected.

## Target files and readers

Line-oriented sources are consumed lazily. Grammar:

- surrounding whitespace is removed from each line;
- empty lines are ignored;
- a line whose first non-space character is `#` is a comment and is ignored;
- inline comments are not supported;
- every other line contains one single target or one CIDR;
- the first invalid line terminates the source with an error;
- emitted targets carry `source-name:line-number` attribution.

Example:

```text
# Production assessment scope approved in ticket SEC-1234
es-a.example.org:9200
192.0.2.0/28
https://[2001:db8::20]:9243/elastic
```

Reader sources do not take ownership of caller-provided readers. File sources own and close the
file descriptor. `Close` is idempotent for all built-in sources.

## CIDR expansion

CIDR sources are pull-based iterators. They retain only the masked prefix and next address; they
do not materialize the address range or start background goroutines. This provides natural
backpressure because an address is produced only when the consumer calls `Next`.

Every address in a prefix is emitted. IPv4 network and broadcast addresses are not removed because
their usability depends on the environment and prefix semantics. Consumers decide whether a
different policy is appropriate.

Cancellation is checked before every emitted address and before every new input line. A canceled
call does not consume the pending target, so a caller may resume with a live context if desired.

## Bounded exact deduplication

The deduplicating source compares canonical targets without source attribution. The first source
attribution is retained. Callers provide a positive maximum number of unique targets.

When that capacity is reached, another new unique target returns `ErrDeduplicationLimit`. The
source does not evict old entries or silently permit distant duplicates; exactness is preserved
within the configured bound and capacity exhaustion is explicit.
