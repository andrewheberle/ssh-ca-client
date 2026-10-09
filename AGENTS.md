# AGENTS.md

## Project overview
This provides the client-side service to interact with the [Serverless
Certificate Authority](https://github.com/andrewheberle/serverless-ssh-ca).

## Repository layout
- `cmd/` - entrypoints for commands; should only include minimal code then call Execute of the relevant package
- `deb/` - Debian package specific files
- `docs/` - documentation of commands
- `internal/pkg/` - application packages; not importable by other modules
- `internal/e2e/` - end-to-end tests against the published server package; `testdata/ca/` pins the CA and its test server (`@andrewheberle/serverless-ssh-ca-testing`), which runs the CA under Node.js or workerd. Changes to how the CA is run belong in the server repo's `packages/testing`
- `internal/pkg/api/` - generated OpenAPI primitives to interact with the server implementation. Do not edit `api.gen.go` or `openapi.json`; `openapi.json` is copied from the CA package pinned in `internal/e2e/testdata/ca/package.json` and CI checks it matches, so update both with `npm run sync-schema --prefix internal/e2e/testdata/ca`.
- `internal/pkg/cli/` - primary package used by the CLI
- `internal/pkg/gui/` - primary package used by the GUI
- `pkg/` - application packages; importable by others
- `policy/` - Group Policy Object's for Windows to manage GUI on Windows; included in MSI build
- `snap/` - Snap specific scripts and files
- `systemd/` - Systemd units for host key renewals; included in APT package
- `templates/` - WiX sources and scripts for the MSI build; built on Linux with `wixl` from msitools (0.106 or later), not the WiX Toolset, so only the WiX v3 subset that `wixl` supports can be used

## Build, test, lint
Run these before considering any change complete:
- Build: `go build ./...`
- Test: `go test -race ./...`
- End-to-end test (needs Node.js 24+ and npm): `go test -tags e2e -race ./internal/e2e/...`; set `E2E_CA_RUNTIME=workerd` to run the CA under workerd instead of Node.js, and run both when changing the harness
- Sync API schema after changing the pinned CA version (needs Node.js and npm): `npm ci --prefix internal/e2e/testdata/ca && npm run sync-schema --prefix internal/e2e/testdata/ca`
- Vet: `go vet ./...`
- Lint: `golangci-lint run`
- Format: `gofmt -s -w .` (or `goimports`); never commit unformatted code

## Code conventions
- Go version: [1.26], per `go.mod`. Don't bump it unless asked.
- Logging: use `log/slog` with structured key/value attributes. No `fmt.Println` or `log.Printf` in service code.
- Errors: wrap with `fmt.Errorf("doing x: %w", err)`. Return errors rather than logging and continuing, unless at the top level or the parent contains a `*slog.Logger`.
- Context: pass `context.Context` as the first parameter for anything doing I/O; respect cancellation.
- Concurrency: guard shared state with `sync.RWMutex` (or channels). Run tests with `-race`.
- Interfaces: define them where they're consumed, keep them small. Decorators (caching, metrics) wrap the interface rather than modifying the implementation.
- Dependencies: prefer the standard library. Ask before adding a new module dependency. Run `go mod tidy` after any dependency change.

## Documentation
- Command line flag or behaviour changes must be reflected in `docs/` and `README.md`

## Testing
- Table-driven tests with `t.Run` subtests.
- Use fakes implementing the package interfaces; no network or external services in unit tests.
- New behaviour needs a test; bug fixes need a test that fails without the fix.

## Releases
- Releases are prepared by release-please (`release-please-config.json`, `.release-please-manifest.json`), which keeps a `chore(release): vX.Y.Z` PR open with the version bump and `CHANGELOG.md` entry, derived from conventional commit messages on `main`.
- Merging the release PR creates the `vX.Y.Z` tag and GitHub release; the tag triggers GoReleaser, which adds the artifacts to that release.
- Don't edit `CHANGELOG.md` or `.release-please-manifest.json` by hand; release-please maintains them.
- PRs are squash merged with the PR title as the commit message, so PR titles must be conventional commits (`feat:`, `fix(scope):`, `feat!:` for breaking changes); the PR title check enforces this. Only `feat`, `fix`, `perf`, `revert` and breaking changes trigger a release.
- Never delete, move, or force-push an existing tag. The Go module proxy caches versions immutably, so a retagged version won't be picked up. Fix forward with a new patch version.
- Don't edit `.goreleaser.yaml` or CI config unless the task is specifically about them.
- Do not create or push a tag unless specifically directed to as this triggers the release workflow.

## Boundaries
- Don't commit secrets, tokens, or real config values.
- Don't modify generated files; regenerate them with `go generate ./...`.
- Keep changes scoped to the task. No drive-by refactors or renames.
