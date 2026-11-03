# Go toolchain pinned in go.mod, with a release per update

Builds, tests, lint and releases use the Go toolchain named by the `toolchain` line in `go.mod`, read by `actions/setup-go` through `go-version-file: go.mod`, rather than whatever `stable` is when a workflow runs. Release binaries are statically linked (`CGO_ENABLED=0`), so the Go standard library ships inside every binary, `.deb`, snap and MSI, and its security fixes only reach users through a release. So Renovate updates the `toolchain` line as a `fix(deps)` commit, and every toolchain update ships as a release; patch updates, which carry Go's security fixes, automerge once the required checks pass. Minor updates are merged by hand, as they can bring new vet and lint findings.

The `go` line stays the minimum supported version and moves only when a newer Go's language features or `GODEBUG` defaults are wanted, after reading that version's `GODEBUG` changes in its release notes. It is also the minimum Go for modules importing `pkg/`, as the `toolchain` line only applies when this module is the main module. Renovate leaves it alone by default, as it treats `go 1.26.0` as `^1.26.0`.

Lint runs on the pinned toolchain only, once per OS. Vet's `stdversion` check reports standard library use newer than the `go` line, which covers what linting on older Go releases would catch for importers of `pkg/`.

## Considered Options

- **`go-version: stable` in every workflow**: no updates to merge. But the compiler changes without any commit or changelog entry, a Go release landing between pull request CI and the release run ships a binary built by a compiler CI never tested, rebuilding a tag later uses a different compiler, and a Go security fix only reaches users when something else happens to trigger a release.
- **Renovate bumping the `go` line** (`rangeStrategy: bump`) with no `toolchain` line: one line, always the current Go, and `setup-go` reads it just the same. But the `go` line also sets the language version, the default `GODEBUG` settings and the minimum Go for importers of `pkg/`, so every minor bump changes how the binary behaves and who can import the module, as well as which compiler builds it. Keeping the two apart means an automerged security patch never changes runtime defaults.
- **Pinning the version in each workflow's `go-version`**: the same effect, but five copies to keep in step, and local builds would not follow them. The `toolchain` line is one copy, which `go` itself honours when building locally.
- **Linting on `oldstable` and `stable`** as well as each OS: twice the lint jobs, for findings `stdversion` already reports against the `go` line.

## Consequences

About one toolchain update a month, plus a minor update every six months. The `fix` override in `renovate.json` is load-bearing: by default a toolchain update would be a `chore(deps)` commit, which never triggers a release, and the pinned toolchain would fall behind Go's security fixes, which is worse than `stable`.

The e2e workflow reads `go.mod` from the client it checks out, so an older release tested with `client-ref: latest` that has no `toolchain` line is tested with the Go version on its `go` line.

golangci-lint refuses to lint for a Go version newer than the one its own binary was built with, and it takes that version from the `toolchain` line. So a minor toolchain update fails lint until golangci-lint releases a binary built with that minor version, which is one more reason minor updates wait for a person to merge them.
