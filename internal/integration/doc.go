// Package integration contains opt-in Elasticsearch container tests.
//
// Default `go test ./...` compiles this package and runs only Docker-free unit
// tests. Container lanes run when GARGA_INTEGRATION=1 and a working Docker
// engine is available. They may pull release images and are not part of
// `make check`.
package integration
