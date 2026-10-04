# Contributing

Open an issue before changing behavior. No DCO or CLA is required.

Use Go 1.26.8 and Git. Install the pinned validation tools:

```sh
go install mvdan.cc/gofumpt@v0.12.0
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
CGO_ENABLED=0 go build -trimpath -o build/packdiff ./cmd/packdiff
sh scripts/validate.sh
```

Syft 1.54.0 is embedded as a library; no external tools are needed. Test fixtures, including RPMs, DEBs, tarballs and source maps, are built in code. Race tests need a C compiler.

Use TDD for code changes: show the failing test before the implementation. Tests are hermetic and use fictional names. `core` is stdlib-only and `detect` and `report` have restricted imports, enforced by depguard. Output must stay deterministic: identical inputs give byte-identical JSON and HTML. packdiff reports differences; it does not judge them, so changes that add pass/fail verdicts or policy are out of scope.

`cmd/packdiff/testdata/golden` holds expected output for an end-to-end run. After an intended output change, regenerate it with `go test ./cmd/packdiff -run RPMEndToEnd -update` and include the reviewed diff. Parsers that read untrusted input have fuzz targets; run them after changing a parser.

After dependency changes run `go mod tidy`. THIRD_PARTY_NOTICES is not committed; the release job generates it from the release binaries. Run `sh scripts/third-party-notices.sh` to inspect it locally. All Go files carry the Apache-2.0 SPDX header.

Release notes come from the CHANGELOG section matching the tag, including prereleases. Actions are pinned by commit SHA; signing uses cosign v3.1.3. Release publication is maintained by the owner.
