#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
files=$(gofumpt -l .)
if [ -n "$files" ]; then printf '%s\n' "$files"; exit 1; fi
go vet ./...
golangci-lint run
CGO_ENABLED=1 go test -race ./...
govulncheck ./...
go mod verify
go mod tidy -diff
