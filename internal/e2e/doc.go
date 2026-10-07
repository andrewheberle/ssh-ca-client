// Package e2e contains end-to-end tests that run the client against the
// published [Serverless SSH CA] package.
//
// The tests require Node.js 22.5 or later and npm, and use the "e2e" build
// tag so they are not run as part of the unit tests:
//
//	go test -tags e2e -race ./internal/e2e/...
//
// The CA is run by the harness in testdata/ca, which provides the parts of
// the Cloudflare Workers environment the CA relies on. Its npm dependencies
// are installed automatically when the tests start, which requires network
// access.
//
// [Serverless SSH CA]: https://github.com/andrewheberle/serverless-ssh-ca
package e2e
