#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
go run ./internal/release notes "$1"
