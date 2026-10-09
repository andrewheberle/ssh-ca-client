// Package e2e contains end-to-end tests that run the client against the
// published [Serverless SSH CA] package.
//
// The tests require Node.js 24 or later and npm, and use the "e2e" build
// tag so they are not run as part of the unit tests:
//
//	go test -tags e2e -race ./internal/e2e/...
//
// The CA is run by the test server from the
// @andrewheberle/serverless-ssh-ca-testing package, which is released with
// the CA and installed with it in testdata/ca. The npm dependencies are
// installed automatically when the tests start, which requires network access.
//
// By default the test server runs the CA under Node.js using the Node.js
// helpers from the CA package with an in-memory node:sqlite database. Setting
// E2E_CA_RUNTIME to "workerd" runs it under workerd, the Cloudflare Workers
// runtime, using the Wrangler test harness with a local D1 database and
// Secrets Store.
//
// Setting E2E_CA_PACKAGE to an npm install spec, such as the path to a
// tarball from "npm pack", tests against that CA package instead of the
// version pinned in testdata/ca/package-lock.json. The package must be
// version 0.20.0 or later, which added the Node.js helpers.
// E2E_CA_TESTING_PACKAGE does the same for the test server package.
//
// [Serverless SSH CA]: https://github.com/andrewheberle/serverless-ssh-ca
package e2e
