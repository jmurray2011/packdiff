// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/jmurray2011/packdiff/core"
)

// class builds a class file whose constant pool holds strs as CONSTANT_Utf8 entries.
func class(strs ...string) string {
	var b bytes.Buffer
	w := func(v any) { _ = binary.Write(&b, binary.BigEndian, v) }
	w(uint32(0xCAFEBABE))
	w(uint32(61))
	w(uint16(len(strs) + 1))
	for _, s := range strs {
		w(uint8(1))
		w(uint16(len(s)))
		b.WriteString(s)
	}
	return b.String()
}

var fp = Options{FirstParty: []string{"com.example"}}

func TestOutbound(t *testing.T) {
	t.Parallel()
	base := snap(
		"app-1.2.3.rpm", nil, nil,
		file{path: "opt/app/webapp/WEB-INF/classes/com/example/Geo.class", content: class(
			"https://old.example.net/api", "Lcom/example/Geo;", "http://www.w3.org/2001/XMLSchema",
		)},
		file{path: "opt/app/conf/app.properties", content: "db.url=jdbc:postgresql://db.example.net:5432/app\n"},
	)
	base.Components = []core.Component{
		{Type: "java-archive", PURL: "pkg:maven/software.amazon.awssdk/s3@2.20.0", Group: "software.amazon.awssdk", Location: core.Location{Chain: []string{"app-1.2.3.rpm", "opt/app/lib/s3-2.20.0.jar"}}},
	}
	head := snap(
		"app-1.2.4.rpm", nil, nil,
		file{path: "opt/app/webapp/WEB-INF/classes/com/example/Geo.class", content: class(
			"https://api.example.net/v2/geocode?q=", "https://api.example.net/v2/reverse", "wss://stream.example.net:8443/feed",
			"https://${geo.host}/x", "http://%s/y", "api.partner.example.org", "org.apache.commons.io", "health.dsl.info",
			"http://www.w3.org/2001/XMLSchema", "http://localhost:8080/health", "Lcom/example/Geo;",
		)},
		file{path: "opt/app/webapp/WEB-INF/classes/org/other/Lib.class", content: class("https://vendor-internal.example.net")},
		file{path: "opt/app/lib/geo-1.0.jar!com/thirdparty/Client.class", content: class("https://thirdparty.example.net")},
		file{path: "opt/app/conf/app.properties", content: "db.url=jdbc:postgresql://db2.example.net:5432/app\nmail.host=smtp.example.com\n"},
	)
	head.Components = []core.Component{
		{Type: "java-archive", PURL: "pkg:maven/software.amazon.awssdk/s3@2.21.0", Group: "software.amazon.awssdk", Location: core.Location{Chain: []string{"app-1.2.4.rpm", "opt/app/lib/s3-2.21.0.jar"}}},
		{Type: "java-archive", PURL: "pkg:maven/software.amazon.awssdk/sqs@2.21.0", Group: "software.amazon.awssdk", Location: core.Location{Chain: []string{"app-1.2.4.rpm", "opt/app/lib/sqs-2.21.0.jar"}}},
		{Type: "java-archive", PURL: "pkg:maven/software.amazon.awssdk/sdk-core@2.21.0", Group: "software.amazon.awssdk"},
		{Type: "java-archive", PURL: "pkg:maven/org.apache.kafka/kafka-clients@3.7.0", Group: "org.apache.kafka"},
		{Type: "java-archive", PURL: "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0", Group: "com.squareup.okhttp3"},
	}
	cs := Run(base, head, fp)

	api := find(t, cs, core.Outbound, "https://api.example.net")
	if api.Kind != core.Added || !slices.Equal(api.Details, []string{"https://api.example.net/v2/geocode?q=", "https://api.example.net/v2/reverse"}) {
		t.Fatalf("api = %+v", api)
	}
	if api.Locations[0].Chain[len(api.Locations[0].Chain)-1] != "opt/app/webapp/WEB-INF/classes/com/example/Geo.class" {
		t.Fatalf("location = %v", api.Locations)
	}
	find(t, cs, core.Outbound, "wss://stream.example.net:8443")
	if c := find(t, cs, core.Outbound, "https://old.example.net"); c.Kind != core.Removed {
		t.Fatalf("old = %+v", c)
	}
	find(t, cs, core.Outbound, "api.partner.example.org")
	find(t, cs, core.Outbound, "smtp.example.com")
	find(t, cs, core.Outbound, "jdbc:postgresql://db2.example.net:5432")
	find(t, cs, core.Outbound, "jdbc:postgresql://db.example.net:5432")
	if c := find(t, cs, core.Outbound, "sdk:aws/sqs"); c.Kind != core.Added {
		t.Fatalf("sqs = %+v", c)
	}
	find(t, cs, core.Outbound, "client:broker/kafka-clients")
	find(t, cs, core.Outbound, "client:http/okhttp")
	for _, s := range []string{"sdk:aws/s3", "sdk:aws/sdk-core", "geo.host", "%s", "org.apache.commons.io", "vendor-internal", "thirdparty.example.net", "w3.org", "dsl.info"} {
		absent(t, cs, core.Outbound, s)
	}
	if c := find(t, cs, core.Outbound, "http://localhost:8080"); !strings.Contains(c.Suppressed, "loopback") {
		t.Fatalf("loopback not suppressed by built-in rule: %+v", c)
	}
}

func TestCrypto(t *testing.T) {
	t.Parallel()
	base := snap(
		"app-1.2.3.rpm", nil, nil,
		file{path: "opt/app/webapp/WEB-INF/classes/com/example/Sec.class", content: class("AES/CBC/PKCS5Padding", "SHA-1", "TLSv1.2", "Lcom/example/Sec;")},
		file{path: "opt/app/conf/app.properties", content: "server.ssl.enabled-protocols=TLSv1.2\njwt.key-size=2048\n"},
		file{path: "opt/app/jre/conf/security/java.security", content: "security.provider.1=SUN\njdk.tls.disabledAlgorithms=SSLv3\n"},
		file{path: "opt/app/cert/truststore.jks", content: "store-v1"},
	)
	base.Components = []core.Component{
		{Type: "java-archive", PURL: "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.77", Group: "org.bouncycastle", Version: "1.77"},
		{Type: "java-archive", PURL: "pkg:maven/org.bouncycastle/bcpkix-jdk18on@1.77", Version: "1.77"}, // no pom.properties
	}
	head := snap(
		"app-1.2.4.rpm", nil, nil,
		file{path: "opt/app/webapp/WEB-INF/classes/com/example/Sec.class", content: class("AES/GCM/NoPadding", "SHA-256", "TLSv1.2", "PBKDF2WithHmacSHA256", "Lcom/example/Sec;")},
		file{path: "opt/app/conf/app.properties", content: "server.ssl.enabled-protocols=TLSv1.2, TLSv1.3\nserver.ssl.ciphers=TLS_AES_256_GCM_SHA384\njwt.key-size=4096\n"},
		file{path: "opt/app/jre/conf/security/java.security", content: "security.provider.1=SUN\nsecurity.provider.2=BCFIPS\njdk.tls.disabledAlgorithms=SSLv3, TLSv1\n"},
		file{path: "opt/app/cert/truststore.jks", content: "store-v2"},
		file{path: "opt/app/cert/server.key", content: "fixture-key-material"},
	)
	head.Components = []core.Component{
		{Type: "java-archive", PURL: "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78", Group: "org.bouncycastle", Version: "1.78"},
		{Type: "java-archive", PURL: "pkg:maven/com.nimbusds/nimbus-jose-jwt@9.37", Group: "com.nimbusds", Version: "9.37"},
		{Type: "java-archive", PURL: "pkg:maven/org.bouncycastle/bcpkix-jdk18on@1.78", Version: "1.78"},
	}
	cs := Run(base, head, fp)

	for _, s := range []string{"alg:AES/GCM/NoPadding", "alg:SHA-256", "alg:PBKDF2WithHmacSHA256", "alg:TLSv1.3", "alg:TLS_AES_256_GCM_SHA384"} {
		if c := find(t, cs, core.Crypto, s); c.Kind != core.Added {
			t.Fatalf("%s = %+v", s, c)
		}
	}
	for _, s := range []string{"alg:AES/CBC/PKCS5Padding", "alg:SHA-1"} {
		if c := find(t, cs, core.Crypto, s); c.Kind != core.Removed {
			t.Fatalf("%s = %+v", s, c)
		}
	}
	absent(t, cs, core.Crypto, "alg:TLSv1.2")
	if c := find(t, cs, core.Crypto, "lib:org.bouncycastle:bcprov-jdk18on"); c.Kind != core.Changed || val(c.After) != "1.78" {
		t.Fatalf("bc = %+v", c)
	}
	find(t, cs, core.Crypto, "lib:com.nimbusds:nimbus-jose-jwt")
	// Reported once, in the more specific category.
	absent(t, cs, core.Deps, "bouncycastle")
	absent(t, cs, core.Deps, "nimbus")
	absent(t, cs, core.Config, "jwt.key-size")
	if c := find(t, cs, core.Crypto, "lib:org.bouncycastle:bcpkix-jdk18on"); c.Kind != core.Changed {
		t.Fatalf("crypto lib without pom.properties = %+v", c)
	}
	if c := find(t, cs, core.Crypto, "opt/app/conf/app.properties#jwt.key-size"); val(c.After) != "4096" {
		t.Fatalf("key size = %+v", c)
	}
	find(t, cs, core.Crypto, "opt/app/jre/conf/security/java.security#security.provider.2")
	find(t, cs, core.Crypto, "opt/app/jre/conf/security/java.security#jdk.tls.disabledAlgorithms")
	ts := find(t, cs, core.Crypto, "store:opt/app/cert/truststore.jks")
	if ts.Kind != core.Changed || !strings.HasPrefix(val(ts.After), "sha256:") || strings.Contains(val(ts.After), "store-v2") {
		t.Fatalf("truststore = %+v", ts)
	}
	if c := find(t, cs, core.Crypto, "store:opt/app/cert/server.key"); strings.Contains(val(c.After), "fixture-key") {
		t.Fatalf("key contents leaked: %+v", c)
	}
}

func TestPlaceholders(t *testing.T) {
	t.Parallel()
	base := snap("app-1.2.3.rpm", nil, nil,
		file{path: "opt/app/webapp/WEB-INF/classes/com/example/Geo.class", content: class("${geo.timeout:30}", "${geo.retries}")})
	head := snap("app-1.2.4.rpm", nil, nil,
		file{path: "opt/app/webapp/WEB-INF/classes/com/example/Geo.class", content: class("${geo.timeout:60}", "prefix ${geo.region:us-east} suffix", "${geo.zone:a}", "${geo.idle-ms:#{12000}}")},
		file{path: "opt/app/webapp/WEB-INF/classes/application.properties", content: "geo.zone=b\n"})
	cs := Run(base, head, fp)
	if c := find(t, cs, core.Config, "${geo.timeout}"); c.Kind != core.Changed || val(c.Before) != "30" || val(c.After) != "60" {
		t.Fatalf("timeout = %+v", c)
	}
	if c := find(t, cs, core.Config, "${geo.region}"); c.Kind != core.Added || val(c.After) != "us-east" {
		t.Fatalf("region = %+v", c)
	}
	if c := find(t, cs, core.Config, "${geo.idle-ms}"); val(c.After) != "#{12000}" {
		t.Fatalf("nested SpEL default truncated: %+v", c)
	}
	absent(t, cs, core.Config, "${geo.zone}") // the config file defines it; reported once, there
	if c := find(t, cs, core.Config, "${geo.retries}"); c.Kind != core.Removed {
		t.Fatalf("retries = %+v", c)
	}
}

func TestRules(t *testing.T) {
	t.Parallel()
	rules, err := ParseRules([]byte(`
suppress:
  - category: outbound
    subject: '^https://telemetry\.example\.net$'
    reason: vendor telemetry, approved standing exception
patterns:
  - category: outbound
    match: 'grpc://([a-z0-9.-]+:\d+)'
    reason: gRPC endpoints
`))
	if err != nil {
		t.Fatal(err)
	}
	base := snap("app-1.2.3.rpm", nil, nil,
		file{path: "opt/app/webapp/WEB-INF/classes/git.properties", content: "git.commit.id=abc\n"})
	head := snap("app-1.2.4.rpm", nil, nil,
		file{path: "opt/app/webapp/WEB-INF/classes/git.properties", content: "git.commit.id=def\n"},
		file{path: "opt/app/webapp/WEB-INF/classes/com/example/T.class", content: class("https://telemetry.example.net", "grpc://rpc.example.net:9000")})
	cs := Run(base, head, Options{FirstParty: []string{"com.example"}, Rules: rules})

	if c := find(t, cs, core.Outbound, "https://telemetry.example.net"); c.Suppressed != "vendor telemetry, approved standing exception" {
		t.Fatalf("user suppression = %+v", c)
	}
	if c := find(t, cs, core.Config, "opt/app/webapp/WEB-INF/classes/git.properties#git.commit.id"); c.Suppressed == "" {
		t.Fatalf("built-in git.properties suppression = %+v", c)
	}
	if c := find(t, cs, core.Outbound, "rpc.example.net:9000"); c.Kind != core.Added || c.Suppressed != "" || !slices.Contains(c.Details, "rule: gRPC endpoints") {
		t.Fatalf("pattern = %+v", c)
	}
	if rules.Digest() == (Rules{}).Digest() || len(rules.Digest()) != 64 {
		t.Fatalf("digest does not reflect user rules: %s", rules.Digest())
	}
}

func TestParseRulesRejects(t *testing.T) {
	t.Parallel()
	for name, doc := range map[string]string{
		"bad regex":       "suppress:\n  - category: outbound\n    subject: '('\n    reason: x\n",
		"no reason":       "suppress:\n  - category: outbound\n    subject: 'x'\n",
		"bad category":    "suppress:\n  - category: nope\n    subject: 'x'\n    reason: x\n",
		"pattern on deps": "patterns:\n  - category: deps\n    match: 'x'\n    reason: x\n",
		"unknown field":   "suppres:\n  - category: outbound\n",
	} {
		if _, err := ParseRules([]byte(doc)); !errors.Is(err, ErrInvalidRules) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestWantsFirstPartyClasses(t *testing.T) {
	t.Parallel()
	w := Wants([]string{"com.example"})
	for _, c := range [][]string{
		{"a.rpm", "opt/app/webapp/WEB-INF/classes/com/example/Geo.class"},
		{"a.rpm", "opt/app/lib/app-core-1.0.jar", "com/example/core/Svc.class"},
		{"a.rpm", "opt/app/jre/conf/security/java.security"},
	} {
		if !w(c) {
			t.Errorf("not wanted: %v", c)
		}
	}
	for _, c := range [][]string{
		{"a.rpm", "opt/app/webapp/WEB-INF/classes/com/examplex/Geo.class"},
		{"a.rpm", "opt/app/lib/geo.jar", "org/other/Geo.class"},
	} {
		if w(c) {
			t.Errorf("wanted: %v", c)
		}
	}
	if Wants(nil)([]string{"a.rpm", "opt/app/webapp/WEB-INF/classes/com/example/Geo.class"}) {
		t.Error("classes wanted without first-party prefixes")
	}
}

func TestBuiltinSuppressesReferenceLinks(t *testing.T) {
	t.Parallel()
	cs := []core.Change{}
	for _, s := range []string{"https://docs.microsoft.com", "https://learn.microsoft.com", "http://www.w3.org", "https://www.apache.org"} {
		cs = append(cs, core.Change{Category: core.Outbound, Subject: s})
	}
	cs = append(cs, core.Change{Category: core.Outbound, Subject: "https://graph.microsoft.com"})
	Rules{}.suppress(cs)
	for _, c := range cs[:len(cs)-1] {
		if c.Suppressed == "" {
			t.Errorf("not suppressed: %s", c.Subject)
		}
	}
	if cs[len(cs)-1].Suppressed != "" {
		t.Error("real API host suppressed")
	}
}

func TestReleaseVersionStampsSuppressed(t *testing.T) {
	t.Parallel()
	base := snap("app-1.2.3-1.rpm", nil, nil,
		file{path: "opt/app/plugin.properties", content: "version=1.2.3\nbuilt.for=app 1.2.3-1\ntimeout=30\nlib=1.2.3\n"})
	base.Artifact.Version = "1.2.3-1"
	base.Package.Provides = []string{"app-r1.2.3"}
	head := snap("app-1.2.4-1.rpm", nil, nil,
		file{path: "opt/app/plugin.properties", content: "version=1.2.4\nbuilt.for=app 1.2.4-1\ntimeout=60\nlib=1.2.5\n"})
	head.Artifact.Version = "1.2.4-1"
	head.Package.Provides = []string{"app-r1.2.4"}
	cs := Run(base, head, Options{})

	for _, s := range []string{"opt/app/plugin.properties#version", "opt/app/plugin.properties#built.for"} {
		if c := find(t, cs, core.Config, s); c.Suppressed != "built-in: release version" {
			t.Errorf("%s not suppressed: %+v", s, c)
		}
	}
	for _, s := range []string{"provides:app-r1.2.3", "provides:app-r1.2.4"} {
		if c := find(t, cs, core.Host, s); c.Suppressed != "built-in: release version" {
			t.Errorf("%s not suppressed: %+v", s, c)
		}
	}
	for _, s := range []string{"opt/app/plugin.properties#timeout", "opt/app/plugin.properties#lib"} {
		if c := find(t, cs, core.Config, s); c.Suppressed != "" {
			t.Errorf("%s wrongly suppressed: %+v", s, c)
		}
	}
}

func TestReleaseVersionStampNeedsRealVersion(t *testing.T) {
	t.Parallel()
	// Single-digit versions are too ambiguous to substitute.
	base := snap("app-1.rpm", nil, nil, file{path: "opt/app/a.properties", content: "workers=1\n"})
	base.Artifact.Version = "1"
	head := snap("app-2.rpm", nil, nil, file{path: "opt/app/a.properties", content: "workers=2\n"})
	head.Artifact.Version = "2"
	if c := find(t, Run(base, head, Options{}), core.Config, "opt/app/a.properties#workers"); c.Suppressed != "" {
		t.Fatalf("suppressed on a one-digit version: %+v", c)
	}
}

func TestKeyMaterialNames(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]bool{
		"server.jks": true, "app.p12": true, "elasticsearch.keystore": true, "tls.pem": true, "cacerts": true, "keystore": true,
		"keystore-cli.jar": false, "truststore-tool.sh": false, "KeystoreLoader.class": false, "keystore.md": false,
	} {
		if got := storeName.MatchString(name); got != want {
			t.Errorf("%s: key material = %v, want %v", name, got, want)
		}
	}
}

func sourceMap(t *testing.T, sources map[string]string) string {
	t.Helper()
	m := struct {
		Version        int      `json:"version"`
		Sources        []string `json:"sources"`
		SourcesContent []string `json:"sourcesContent"`
	}{Version: 3}
	for _, k := range slices.Sorted(maps.Keys(sources)) {
		m.Sources = append(m.Sources, k)
		m.SourcesContent = append(m.SourcesContent, sources[k])
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSourceMapLiterals(t *testing.T) {
	t.Parallel()
	base := snap("app-1.rpm", nil, nil, file{path: "opt/app/web/main.js.map", content: sourceMap(t, map[string]string{
		"webpack://app/./src/api.ts": `export const API = "https://old-api.example.net/v1";`,
	})})
	head := snap("app-2.rpm", nil, nil, file{path: "opt/app/web/main.js.map", content: sourceMap(t, map[string]string{
		"webpack://app/./src/api.ts": "// docs: https://docs.example.org/guide\n" +
			"export const API = 'https://api.example.net/v1';\n" +
			"const key = await crypto.subtle.generateKey({ name: \"AES-GCM\", length: 256 }, true, [\"encrypt\"]);\n" +
			"const ws = `wss://stream.example.net/feed`;\n",
		"webpack://app/./node_modules/lib/index.js": `fetch("https://cdn.thirdparty.example.com/x")`,
		"webpack://app/../vendor/pdf/src/util.js":   `const u = "https://vendored.example.com";`,
		"webpack://app/./src/download.ts":           "const base = `https://§replace-me§.example.net`;",
		"webpack://app/webpack/bootstrap":           `var u = "https://bootstrap.example.com"`,
	})})
	cs := Run(base, head, Options{})

	api := find(t, cs, core.Outbound, "https://api.example.net")
	if api.Kind != core.Added {
		t.Fatalf("api = %+v", api)
	}
	if got := api.Locations[0].Chain; !slices.Equal(got, []string{"app-2.rpm", "opt/app/web/main.js.map", "src/api.ts"}) {
		t.Fatalf("location chain = %v", got)
	}
	find(t, cs, core.Outbound, "wss://stream.example.net")
	if c := find(t, cs, core.Outbound, "https://old-api.example.net"); c.Kind != core.Removed {
		t.Fatalf("old = %+v", c)
	}
	find(t, cs, core.Crypto, "alg:AES-GCM")
	absent(t, cs, core.Outbound, "docs.example.org")       // comment
	absent(t, cs, core.Outbound, "thirdparty.example.com") // node_modules
	absent(t, cs, core.Outbound, "bootstrap.example.com")  // bundler runtime
	absent(t, cs, core.Outbound, "vendored.example.com")   // outside the project root
	absent(t, cs, core.Outbound, "replace-me")             // not a host name
	if !Wants(nil)([]string{"a.rpm", "opt/app/web/main.js.map"}) {
		t.Fatal("source maps not captured")
	}
	if Wants(nil)([]string{"a.rpm", "opt/app/lib/webjar-1.0.jar", "META-INF/resources/x.js.map"}) {
		t.Fatal("source map inside a library jar captured")
	}
}
