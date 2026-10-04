# packdiff

Compares two release artifacts and reports what changed in configuration, outbound
network reach, cryptography, database schema, host footprint, dependencies, and file
contents.

It only reads the artifacts. Nothing inside them is executed.

## Install

Download the binary for your platform, `SHA256SUMS`, and `SHA256SUMS.sigstore.json` from
[Releases](https://github.com/jmurray2011/packdiff/releases). Verify with cosign v3.1.3,
replacing the tag with the release you downloaded:

```
tag=v0.1.0
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/jmurray2011/packdiff/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
chmod +x packdiff-linux-amd64
./packdiff-linux-amd64 --version
```

Your binary must show OK in the checksum output. Each binary also has a `.sigstore.json`
bundle and a `.cdx.json` SBOM. Verify build provenance with
`gh attestation verify packdiff-linux-amd64 --repo jmurray2011/packdiff`.

To build from source (Go 1.26.8 or later):

```
go install github.com/jmurray2011/packdiff/cmd/packdiff@latest
# or, with a version stamp:
CGO_ENABLED=0 go build -trimpath -ldflags "-X main.buildVersion=1.0.0" -o packdiff ./cmd/packdiff
```

The binary is static and has no runtime dependencies.

## Usage

```
packdiff --base app-1.2.3.rpm --head app-1.2.4.rpm --first-party com.example \
    --out packdiff.json --html packdiff.html
```

| Flag | Meaning |
|---|---|
| `--base` | Older artifact |
| `--head` | Newer artifact |
| `--first-party` | Java package prefix whose classes are scanned for literals. Repeatable. Without it, no class files are read. |
| `--rules` | Rules file: suppressions and extra patterns (see below) |
| `--out` | Write the JSON result to this path, or `-` for stdout |
| `--html` | Write the HTML report to this path |
| `--format` | Terminal output: `summary` (default), `full`, or `none` |
| `--version` | Print the version, commit, and Go version, then exit |

When `--out -` is used, terminal output goes to stderr.

## Exit status

| Code | Meaning |
|---|---|
| 0 | The comparison completed, whatever it found |
| 2 | Usage error, unreadable artifact, or bad rules file |

To act on what changed, read the JSON result.

## Inputs

RPM (including RPM 6 payloads), DEB, WAR, JAR, EAR, ZIP (including self-executing jars
with a launch script in front), and tar, plain or compressed with gzip, xz, zstd, or
bzip2. The format is detected from the content, not the file name. Nested archives, zip
or tar, are walked, so a jar inside a war inside an RPM is read. Every change records the full chain of archives leading to
its evidence, for example:

```
app-1.2.4.rpm > opt/app/app.war > WEB-INF/lib/geo-2.0.jar > com/example/Geo.class
```

RPM and DEB headers are read for install scripts, file modes and owners, config-file
flags, requires/provides, and (RPM only) file capabilities.

## Categories

**config**
- Keys and values in `*.properties`, `application*.yml`, `bootstrap*.yml`, `*.ini`
  (as `section.key`), `.env` files, `setenv.sh`, the shell variable files under
  `etc/sysconfig/` and `etc/default/`, and systemd `Environment=` / `EnvironmentFile=`.
- JVM options in `*_OPTS` variables (`-D`, `-Xmx`, `-XX:`).
- `${key}` and `${key:default}` placeholders in first-party classes, when no config
  file in the same release defines the key.
- Values whose key looks secret (password, token, key, credential, and so on) are
  shown as `<redacted:hash>`, so a changed secret is visible without its value.

**outbound**
- URLs (http, ws, ldap, smtp, amqp, mqtt, redis, mongodb, kafka, and others), JDBC
  URLs, and bare host names in first-party classes, config values, and first-party
  JavaScript (see below). URLs are reported by scheme, host, and port; the full URLs
  are in the change details.
- First-party JavaScript is read from source maps that embed their sources. Sources
  under `node_modules/`, outside the project root (`../`), or from the bundler's own
  runtime are skipped, and only string literals are read, not comments. The location
  chain ends in the original source file, for example
  `app.rpm > opt/app/web/main.js.map > src/api.ts`.
- AWS, Azure, and GCP SDK service clients, HTTP client libraries, and message broker
  clients found in the dependency list.

**crypto**
- Cipher transformations, digests, MACs, signature algorithms, KDFs, TLS versions,
  cipher suites, JWT algorithm names, and WebCrypto algorithm names (`AES-GCM`,
  `RSA-OAEP`, `ECDSA`, and others) in first-party classes, config values, and
  first-party JavaScript.
- Crypto and token libraries and their versions (Bouncy Castle, Conscrypt, Nimbus,
  jjwt, Tink, and others).
- `java.security` settings, and config keys ending in `key-size`, `key-length`, or
  `key-bits`.
- Keystores, truststores, certificates, and key files, by SHA-256 only. Their
  contents are never read into the output.

**schema**
- Every `.sql` file and Liquibase changelog outside third-party jars: added, removed,
  or modified.
- Added SQL files get a statement summary: tables created and dropped, columns added,
  dropped, and altered, indexes, extensions, and grants.
- A modified Flyway versioned migration (`V*__*.sql`) is noted as such, because its
  checksum no longer matches databases that ran the old version.

**host**
- Install scripts, with a line diff when changed.
- Users and groups created by install scripts.
- Package requires and provides.
- Mode, owner, config flag, capabilities, and link target of every file in the
  payload. Added and removed files are reported only if they are executable,
  setuid/setgid, have capabilities, are config files, are under `etc/`, or are
  systemd units. When more than 20 files share the same attribute change, as when a
  build's umask changes, they are reported as one change listing every path.
- systemd unit settings: `Exec*`, `User`, `Group`, ordering and dependency keys, and
  sandboxing directives.
- Listening ports from `server.port`, Tomcat `server.xml`, and port arguments in unit
  `Exec*` lines.

**deps**
- Components found by Syft: added, removed, and version changed.
- Maven components are keyed `group:artifact`. When a jar has no `pom.properties`,
  Syft guesses the group; a guess is kept only if it is the same in both releases and
  looks like a real group, otherwise the component is keyed by artifact alone. This
  stops one library showing up as removed and added because its guessed group changed.
- Crypto libraries are reported under crypto only.

**files**
- Files in the payload that were added, removed, or whose content changed (by SHA-256),
  when no other category already reports a change in them. A config file with a changed
  key appears under config; one with only a comment edit appears here.
- Entries inside nested archives are not listed; a changed jar appears once, as the jar.
- Large changes are rolled up into one entry that lists every path:
  - files added or removed together with their whole directory tree become `dir/**`;
  - two or more recompiled classes under a `classes/` root become
    `.../classes/**/*.class`;
  - more than 20 changes of the same kind in one directory become `dir/*`.

## Rules

```yaml
suppress:
  - category: outbound
    subject: '^https://telemetry\.example\.net$'
    reason: Vendor telemetry endpoint
patterns:
  - category: outbound
    match: 'grpc://([a-z0-9.-]+:\d+)'
    reason: gRPC endpoints
```

- `suppress` entries match a change's subject by regular expression. Suppressed
  changes are listed separately from the main changes, with the reason, in the JSON
  `suppressed` array, the HTML report, and `--format full`.
- `patterns` add outbound or crypto subjects for each match in first-party class
  literals and config values. The first capture group, if present, is the subject.
- `reason` is required on every entry. Unknown fields are rejected.

Built-in suppressions always apply: XML namespace and schema URIs, license and
documentation links, loopback addresses, `git.properties` / `build-info.properties`, and
release version stamps. A version stamp is a change that only moves the release's own
version, such as `version=8.14.0` becoming `version=8.14.1` in a plugin descriptor;
dependency changes are never treated as stamps.
The result records a digest of the built-in and user rules together.

## Output

**Terminal.** One counts line, then one line per change:

```
app 1.2.3 -> 1.2.4 | config +3 ~1 | outbound +1 | crypto 0 | schema +2 | host ~1 | deps +4 -1 ~12 | files ~2
config changed opt/app/conf/app.properties#timeout  (30 -> 60)
outbound added https://api.example.net
```

`summary` lists every change, one per line. `full` adds each change's details and
locations, plus the suppressed changes.

**JSON.** `schema_version`, `tool` (name, version, rules digest), `base` and `head`
(path, SHA-256, type, name, version), `options`, per-category `summary` counts, and the
`changes` and `suppressed` arrays. Each change has a stable `id`, `category`, `kind`
(`added`, `removed`, `changed`), `subject`, `before`, `after`, optional `details`, and
`locations`.

Change IDs hash the category, the subject, and the location with versions stripped
from archive and directory names, so the same change keeps its ID across releases.
Subjects are stripped the same way, so `apache-tomcat-10.1.30/conf/server.xml` and
`apache-tomcat-10.1.31/conf/server.xml` are the same file.

**HTML.** A single file with everything inline: no fonts, scripts, or styles are
loaded from anywhere. It has the per-category counts, a table per category with
before and after values, the evidence for each change, a text filter, the suppressed
changes, and the SHA-256 of both artifacts.

Output is deterministic: the same inputs give byte-identical JSON and HTML.

## Limits

- Key sizes are read from config only. Small integer literals such as 2048 are
  compiled into bytecode, not the constant pool, and packdiff does not decompile.
- Literal scanning covers first-party classes and config files. Third-party code is
  covered only through the dependency list.
- Frontend JavaScript is scanned only through source maps that embed their sources
  (`sourcesContent`). Minified bundles without maps, and maps inside library jars, are
  not scanned.
- Bare host names are recognized by their top-level domain, so a dotted identifier such
  as `kc.org` can be reported as a host. Suppress such subjects with a rule.
- Nested archives larger than 512 MB are recorded and hashed but not walked.
- These stop the run with exit status 2, to bound memory on hostile input: archives
  nested more than 8 levels deep, more than 1 GB of nested archives held in memory at
  once, or more than 1 GB of config and class content kept from one artifact.

## Development

```
sh scripts/validate.sh
```

This runs gofumpt, go vet, golangci-lint, race-enabled tests, govulncheck, `go mod verify`,
and `go mod tidy -diff`. CI runs the same script with gofumpt v0.12.0, golangci-lint
v2.14.0, and govulncheck v1.8.0.

Tests build their fixtures in code with fictional names.

`cmd/packdiff/testdata/golden` holds the expected JSON, HTML, and terminal output for an
end-to-end RPM run. After an intended output change, rewrite them and review the diff:

```
go test ./cmd/packdiff -run RPMEndToEnd -update
```

Fuzz targets for the parsers that read untrusted input:

```
go test ./core -run '^$' -fuzz FuzzClassStrings
go test ./artifact -run '^$' -fuzz FuzzWalk
go test ./artifact -run '^$' -fuzz FuzzCpio
go test ./detect -run '^$' -fuzz FuzzParsers
```

## Releasing

1. Rename `## [Unreleased]` in `CHANGELOG.md` to the new version, for example
   `## [0.1.0]`, and commit it on `main`.
2. Tag that commit and push the tag: `git tag v0.1.0 && git push origin v0.1.0`.

The release workflow rejects tags that are not on `main` or have no CHANGELOG section. It
builds Linux (amd64, arm64), macOS (amd64, arm64), and Windows (amd64) binaries, generates
per-binary SBOMs and THIRD_PARTY_NOTICES, writes SHA256SUMS, attests build provenance,
signs with cosign through GitHub OIDC, and publishes the release. Tags with a pre-release
suffix such as `v0.1.0-rc1` are published as pre-releases.

## License

[Apache-2.0](LICENSE), Copyright 2026 Josh Murray. [NOTICE](NOTICE) points to
THIRD_PARTY_NOTICES, which is generated from the release binaries and attached to each
release; it includes upstream notices, elected dual licenses, and MPL source URLs. Run
`sh scripts/third-party-notices.sh` to generate it locally.
