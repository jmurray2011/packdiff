// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/jmurray2011/packdiff/core"
)

// literal is one string seen in a first-party class constant pool or a config value. file
// points into the snapshot: a class can hold thousands of literals, so copying the File
// into each one dominated memory on large artifacts.
type literal struct {
	text string
	file *core.File
}

// firstPartyClass reports whether chain ends in a class under one of the package prefixes.
func firstPartyClass(chain []string, prefixes []string) bool {
	name := chain[len(chain)-1]
	if !strings.HasSuffix(name, ".class") {
		return false
	}
	if i := strings.LastIndex(name, "/classes/"); i >= 0 {
		name = name[i+len("/classes/"):]
	}
	for _, p := range prefixes {
		if strings.HasPrefix(name, strings.ReplaceAll(p, ".", "/")+"/") {
			return true
		}
	}
	return false
}

func literals(s core.Snapshot, firstParty []string) []literal {
	var out []literal
	for i := range s.Files {
		f := &s.Files[i]
		if f.Content == nil {
			continue
		}
		if firstPartyClass(f.Chain, firstParty) {
			strs, err := core.ClassStrings(f.Content)
			if err != nil {
				continue // not a class file despite the name; nothing to read
			}
			for _, t := range strs {
				out = append(out, literal{t, f})
			}
			continue
		}
		if f.InLibrary() {
			continue
		}
		if isSourceMap(f.Name()) {
			out = append(out, sourceMapLiterals(f)...)
			continue
		}
		for k, v := range keyValues(*f) {
			if !secretKey.MatchString(k) && v != "" {
				out = append(out, literal{v, f})
			}
		}
	}
	return out
}

var (
	urlRE  = regexp.MustCompile(`(?i)\b(?:https?|wss?|ftps?|ldaps?|smtps?|amqps?|mqtts?|rediss?|mongodb(?:\+srv)?|nats|kafka)://[^\s"'<>{}|\\^` + "`" + `,;]+`)
	jdbcRE = regexp.MustCompile(`(?i)\bjdbc:[a-z0-9]+:(?:[a-z0-9]+:)*(?://|@)[^\s"'<>;,]+`)
	// info and biz are left out: dotted identifiers such as "health.dsl.info" end in them far
	// more often than real host names do.
	fqdnRE = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|gov|mil|us|edu|cloud|ai|dev|app|co|uk|ie|eu|de|fr|ca|au|in|jp)$`)
	hostRE = regexp.MustCompile(`^(?:[a-z0-9_-]+(?:\.[a-z0-9_-]+)*|\[[0-9a-f:.]+\])(?::\d+)?$`)
	// Reverse-DNS package names start with a TLD; hosts end with one.
	packageStart = []string{"com", "org", "net", "io", "java", "javax", "jakarta", "sun", "edu", "gov"}
)

// origin reduces a URL to scheme://host[:port]; ok is false for templated or hostless URLs.
func origin(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	host := strings.ToLower(u.Host)
	if !hostRE.MatchString(host) {
		return "", false // empty, templated ("${x}", "%s"), or placeholder ("§replace-me§")
	}
	return strings.ToLower(u.Scheme) + "://" + host, true
}

// jdbcOrigin reduces a JDBC URL to its driver prefix and host[:port]; embedded databases have none.
func jdbcOrigin(raw string) (string, bool) {
	sep := "//"
	i := strings.Index(raw, sep)
	if i < 0 {
		sep = "@"
		if i = strings.Index(raw, sep); i < 0 {
			return "", false
		}
	}
	host := raw[i+len(sep):]
	if j := strings.IndexAny(host, "/?;"); j >= 0 {
		host = host[:j]
	}
	if sep == "@" {
		// Oracle thin: @host:port:sid
		if parts := strings.Split(host, ":"); len(parts) > 2 {
			host = parts[0] + ":" + parts[1]
		}
	}
	if host = strings.ToLower(host); !hostRE.MatchString(host) {
		return "", false
	}
	return strings.ToLower(raw[:i]) + sep + host, true
}

func outboundFacts(s core.Snapshot, lits []literal, rules Rules, keys componentKeys) facts {
	fs := facts{}
	add := func(subject, detail string, f core.File) {
		fs.add(subject, "", f)
		if detail != "" {
			cur := fs[subject]
			if !slices.Contains(cur.details, detail) {
				cur.details = append(cur.details, detail)
				slices.Sort(cur.details)
			}
			fs[subject] = cur
		}
	}
	for _, l := range lits {
		for _, m := range urlRE.FindAllString(l.text, -1) {
			if o, ok := origin(m); ok {
				add(o, m, *l.file)
			}
		}
		for _, m := range jdbcRE.FindAllString(l.text, -1) {
			if o, ok := jdbcOrigin(m); ok {
				add(o, "", *l.file)
			}
		}
		if t := strings.TrimSpace(l.text); fqdnRE.MatchString(t) && !slices.Contains(packageStart, t[:strings.IndexByte(t, '.')]) {
			add(t, "", *l.file)
		}
	}
	patternFacts(core.Outbound, lits, rules, add)
	for _, c := range s.Components {
		if subject := outboundClient(keys.key(c)); subject != "" {
			fs.add(subject, "", core.File{Chain: c.Location.Chain})
		}
	}
	return fs
}

func patternFacts(cat core.Category, lits []literal, rules Rules, add func(subject, detail string, f core.File)) {
	for _, p := range rules.Patterns {
		if p.Category != cat {
			continue
		}
		for _, l := range lits {
			for _, m := range p.re.FindAllStringSubmatch(l.text, -1) {
				subject := m[0]
				if len(m) > 1 && m[1] != "" {
					subject = m[1]
				}
				add(subject, "rule: "+p.Reason, *l.file)
			}
		}
	}
}

// awsCore are AWS SDK v2 modules that are plumbing rather than a service client.
var awsCore = map[string]bool{
	"sdk-core": true, "aws-core": true, "regions": true, "auth": true, "utils": true, "annotations": true,
	"http-client-spi": true, "metrics-spi": true, "profiles": true, "json-utils": true, "protocol-core": true,
	"aws-json-protocol": true, "aws-query-protocol": true, "aws-xml-protocol": true, "aws-cbor-protocol": true,
	"third-party-jackson-core": true, "endpoints-spi": true, "http-auth": true, "http-auth-aws": true,
	"http-auth-spi": true, "http-auth-aws-eventstream": true, "identity-spi": true, "checksums": true,
	"checksums-spi": true, "retries": true, "retries-spi": true, "apache-client": true, "netty-nio-client": true,
	"url-connection-client": true, "arns": true, "crt-core": true, "aws-crt-client": true, "bom": true,
	"sdk-bom": true, "utils-lite": true,
}

var clientLibs = map[string]string{
	"com.squareup.okhttp3:okhttp":                     "client:http/okhttp",
	"org.apache.httpcomponents:httpclient":            "client:http/httpclient",
	"org.apache.httpcomponents.client5:httpclient5":   "client:http/httpclient5",
	"org.eclipse.jetty:jetty-client":                  "client:http/jetty-client",
	"org.asynchttpclient:async-http-client":           "client:http/async-http-client",
	"io.github.openfeign:feign-core":                  "client:http/feign",
	"com.squareup.retrofit2:retrofit":                 "client:http/retrofit",
	"org.apache.kafka:kafka-clients":                  "client:broker/kafka-clients",
	"com.rabbitmq:amqp-client":                        "client:broker/amqp-client",
	"io.nats:jnats":                                   "client:broker/jnats",
	"org.apache.pulsar:pulsar-client":                 "client:broker/pulsar-client",
	"org.apache.activemq:activemq-client":             "client:broker/activemq-client",
	"org.apache.activemq:artemis-jms-client":          "client:broker/artemis-jms-client",
	"org.eclipse.paho:org.eclipse.paho.client.mqttv3": "client:broker/paho-mqttv3",
	"org.eclipse.paho:org.eclipse.paho.mqttv5.client": "client:broker/paho-mqttv5",
}

// outboundClient names the network client a component key provides, or "".
func outboundClient(key string) string {
	group, artifact, ok := strings.Cut(key, ":")
	if !ok {
		return ""
	}
	switch {
	case group == "software.amazon.awssdk" && !awsCore[artifact]:
		return "sdk:aws/" + artifact
	case group == "com.amazonaws" && strings.HasPrefix(artifact, "aws-java-sdk-") && artifact != "aws-java-sdk-core":
		return "sdk:aws-v1/" + strings.TrimPrefix(artifact, "aws-java-sdk-")
	case group == "com.azure" && strings.HasPrefix(artifact, "azure-") && !strings.HasPrefix(artifact, "azure-core") &&
		artifact != "azure-json" && artifact != "azure-xml":
		return "sdk:azure/" + strings.TrimPrefix(artifact, "azure-")
	case group == "com.google.cloud" && strings.HasPrefix(artifact, "google-cloud-") && !strings.HasPrefix(artifact, "google-cloud-core"):
		return "sdk:gcp/" + strings.TrimPrefix(artifact, "google-cloud-")
	}
	return clientLibs[key]
}

var (
	cryptoLiteral = regexp.MustCompile(`^(?:` +
		`(?:AES|DES|DESede|TripleDES|RSA|ChaCha20(?:-Poly1305)?|Blowfish|RC2|RC4|ARCFOUR|ECIES)(?:/[A-Za-z0-9]+/[A-Za-z0-9]+)?` +
		`|MD2|MD4|MD5|SHA|SHA-?1|SHA-?224|SHA-?256|SHA-?384|SHA-?512(?:/224|/256)?|SHA3-(?:224|256|384|512)` +
		`|Hmac(?:MD5|SHA1|SHA224|SHA256|SHA384|SHA512)` +
		`|(?:SHA\d+|MD5|SHA3-\d+)with(?:RSA|ECDSA|DSA|RSAandMGF1)|Ed25519|Ed448|RSASSA-PSS` +
		`|PBKDF2WithHmac(?:SHA1|SHA256|SHA384|SHA512)` +
		`|SSLv2Hello|SSLv3|TLSv1(?:\.[0-3])?|DTLSv1\.[02]` +
		`|(?:TLS|SSL)_[A-Z0-9_]{6,}` +
		`|(?:HS|RS|ES|PS)(?:256|384|512)` +
		`|AES-(?:GCM|CBC|CTR|KW)|RSA-OAEP|RSASSA-PKCS1-v1_5|RSA-PSS|ECDSA|ECDH|HMAC|HKDF|PBKDF2|X25519` +
		`)$`)
	keySizeKey = regexp.MustCompile(`(?i)key[._-]?(size|length|bits)$`)
	storeName  = regexp.MustCompile(`(?i)(\.(jks|jceks|p12|pfx|keystore|truststore|bcfks|pem|crt|cer|der|key|p8|p7b)$|^(keystore|truststore|cacerts)$)`)
	// cryptoLibs are artifact groups (or group:artifact) of cryptography providers and token libraries.
	cryptoLibs = []string{
		"org.bouncycastle:", "org.conscrypt:", "com.nimbusds:nimbus-jose-jwt", "io.jsonwebtoken:", "com.auth0:java-jwt",
		"org.bitbucket.b_c:jose4j", "com.google.crypto.tink:", "org.springframework.security:spring-security-crypto",
		"org.jasypt:", "de.mkammerer:argon2", "at.favre.lib:bcrypt", "org.mindrot:jbcrypt", "com.amazonaws:aws-encryption-sdk-java",
		"software.amazon.cryptography:", "software.amazon.cryptools:", "io.netty:netty-tcnative", "org.wildfly.openssl:",
	}
)

// cryptoLib reports whether a component key names a crypto or token library.
func cryptoLib(key string) bool {
	for _, lib := range cryptoLibs {
		if strings.HasPrefix(key, lib) {
			return true
		}
	}
	return false
}

func isSecurityConfig(name string) bool {
	return name == "java.security" || strings.HasSuffix(name, ".security")
}

func cryptoFacts(s core.Snapshot, lits []literal, rules Rules, keys componentKeys) facts {
	fs := facts{}
	add := func(subject, detail string, f core.File) {
		fs.add(subject, "", f)
		if detail != "" {
			cur := fs[subject]
			if !slices.Contains(cur.details, detail) {
				cur.details = append(cur.details, detail)
			}
			fs[subject] = cur
		}
	}
	for _, l := range lits {
		for _, tok := range strings.FieldsFunc(l.text, func(r rune) bool { return r == ',' || r == ' ' || r == ':' }) {
			if cryptoLiteral.MatchString(tok) {
				add("alg:"+tok, "", *l.file)
			}
		}
	}
	patternFacts(core.Crypto, lits, rules, add)

	for _, f := range s.Files {
		if f.InLibrary() {
			continue
		}
		where := core.Unversioned(f.Chain)
		switch name := f.Name(); {
		case f.Content != nil && isSecurityConfig(name):
			for k, v := range properties(string(f.Content)) {
				fs.add(where+"#"+k, v, f)
			}
		case f.Content != nil && isConfigFile(f):
			for k, v := range keyValues(f) {
				if keySizeKey.MatchString(k) {
					fs.add(where+"#"+k, v, f)
				}
			}
		case storeName.MatchString(name) && f.Mode&0o170000 == 0o100000:
			fs.add("store:"+where, "sha256:"+f.SHA256[:min(16, len(f.SHA256))], f)
		}
	}
	for _, c := range s.Components {
		if key := keys.key(c); cryptoLib(key) {
			fs.add("lib:"+key, c.Version, core.File{Chain: c.Location.Chain})
		}
	}
	return fs
}

// The default may hold one level of braces, e.g. a SpEL expression: ${key:#{12000}}.
var placeholderRE = regexp.MustCompile(`\$\{([A-Za-z0-9_.\-\[\]]+)(?::((?:[^{}]|\{[^{}]*\})*))?\}`)

// placeholderFacts reads ${key} and ${key:default} from first-party class constants. Keys a
// config file in the same release defines are left to the config file's own change.
func placeholderFacts(s core.Snapshot, lits []literal) facts {
	defined := map[string]bool{}
	for _, f := range s.Files {
		if f.Content != nil && !f.InLibrary() {
			for k := range keyValues(f) {
				defined[k] = true
			}
		}
	}
	fs := facts{}
	for _, l := range lits {
		if path.Ext(l.file.Name()) != ".class" {
			continue
		}
		for _, m := range placeholderRE.FindAllStringSubmatch(l.text, -1) {
			if defined[m[1]] {
				continue
			}
			fs.add("${"+m[1]+"}", m[2], *l.file)
		}
	}
	return fs
}
