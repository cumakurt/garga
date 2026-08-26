# Probe contract

The probe layer performs one read-only HTTP `GET` through the shared transport and converts the
bounded response into product-neutral fingerprint input. It does not decide whether a response
is Elasticsearch and does not retain arbitrary request metadata.

## Retained response data

A successful result contains:

- the status code and HTTP protocol;
- a bounded response body already enforced by the transport;
- request method `GET` and only a `root` or `custom_path` resource classification;
- the following response headers in a fixed order:
  - `Content-Type`;
  - `Server`;
  - `Warning`;
  - `Www-Authenticate`;
  - `X-Elastic-Product`;
  - `X-Found-Handling-Cluster`;
  - `X-Found-Handling-Instance`.

Each retained header is limited to eight unique values and 1024 bytes in total. Values are
converted to valid UTF-8, control characters become spaces, duplicates are removed, and the
remaining values are sorted. A truncation marker tells downstream fingerprint logic that it did
not receive the complete field.

Cookies, authorization data, arbitrary headers, the raw host, and the raw user-supplied path are
not part of probe metadata. The scanner remains responsible for associating a result with its
target outside the fingerprint input.

## Error taxonomy

Probe errors classify failures as `invalid_endpoint`, `canceled`, `timeout`, `tcp`, `tls`, or
`http`. They wrap the transport or endpoint cause for `errors.Is`/`errors.As` control flow, while
their formatted text contains no endpoint, URL, headers, credentials, or server response data.
DNS, connect, and general network failures map to `tcp`; redirects, malformed HTTP, read failures,
and response-limit failures map to `http`.

Equivalent bounded HTTP responses produce structurally equal probe results. Timing and other
machine-dependent fields are intentionally absent.
