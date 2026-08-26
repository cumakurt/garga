package transport

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
)

func TestKindOf(t *testing.T) {
	t.Parallel()

	cause := errors.New("cause")
	err := &Error{kind: ErrorConnect, operation: "request", cause: cause}
	kind, ok := KindOf(err)
	if !ok || kind != ErrorConnect {
		t.Fatalf("KindOf() = %q, %t; want %q, true", kind, ok, ErrorConnect)
	}
	if !errors.Is(err, cause) {
		t.Fatal("transport error did not preserve its cause")
	}
	if _, ok := KindOf(errors.New("other")); ok {
		t.Fatal("KindOf() classified a non-transport error")
	}
}

func TestClassifyRequestError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want ErrorKind
	}{
		{"canceled", context.Canceled, ErrorCanceled},
		{"deadline", context.DeadlineExceeded, ErrorTimeout},
		{"redirect", errRedirectLimit, ErrorRedirect},
		{"DNS", &net.DNSError{Err: "not found", Name: "example.invalid"}, ErrorDNS},
		{"connect", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("refused")}, ErrorConnect},
		{"protocol", errors.New("malformed HTTP response"), ErrorProtocol},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := classifyRequestError(&url.Error{Op: "Get", URL: "https://user:secret@example.invalid", Err: test.err})
			if got.Kind() != test.want {
				t.Fatalf("kind = %q, want %q", got.Kind(), test.want)
			}
			if strings.Contains(got.Error(), "secret") || strings.Contains(got.Error(), "example.invalid") {
				t.Fatalf("formatted error exposed request URL: %q", got)
			}
		})
	}
}
