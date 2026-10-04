// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/jmurray2011/packdiff/core"
)

var (
	appYAML    = regexp.MustCompile(`^(application|bootstrap)([-.][\w.-]+)?\.ya?ml$`)
	secretKey  = regexp.MustCompile(`(?i)(passw|secret|token|credential|private[._-]?key|api[._-]?key|access[._-]?key|pwd)`)
	shellAssig = regexp.MustCompile(`^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)
	jvmOption  = regexp.MustCompile(`^(-D[^=]+)=(.*)$|^(-X(?:mx|ms|ss|mn))(.+)$|^(-XX:[+-]?)([\w.]+)(?:=(.*))?$`)
)

// shellEnvFile reports files of shell variable assignments: .env files, Tomcat's setenv.sh,
// and the service defaults under /etc/sysconfig and /etc/default.
func shellEnvFile(f core.File) bool {
	name := f.Name()
	if name == "setenv.sh" || name == ".env" || strings.HasSuffix(name, ".env") || strings.Contains(name, ".env.") {
		return true
	}
	p := f.Chain[len(f.Chain)-1]
	return len(f.Chain) == 2 && (strings.HasPrefix(p, "etc/sysconfig/") || strings.HasPrefix(p, "etc/default/"))
}

func isConfigFile(f core.File) bool {
	name := f.Name()
	return strings.HasSuffix(name, ".properties") || appYAML.MatchString(name) || strings.HasSuffix(name, ".ini") || shellEnvFile(f)
}

// keyValues parses one config file into key -> value; nil when the file is not config.
func keyValues(f core.File) map[string]string {
	name := f.Name()
	switch {
	case strings.HasSuffix(name, ".properties"):
		return properties(string(f.Content))
	case appYAML.MatchString(name):
		return yamlKeys(f.Content)
	case strings.HasSuffix(name, ".ini"):
		return iniKeys(string(f.Content))
	case shellEnvFile(f):
		return shellKeys(string(f.Content))
	case isUnit(name):
		return unitEnvironment(string(f.Content))
	}
	return nil
}

// iniKeys reads "key = value" lines, prefixing keys with their [section].
func iniKeys(text string) map[string]string {
	out := map[string]string{}
	section := ""
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || line[0] == ';' || line[0] == '#':
		case line[0] == '[' && strings.HasSuffix(line, "]"):
			section = strings.TrimSpace(line[1 : len(line)-1])
		default:
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			k = strings.TrimSpace(k)
			if section != "" {
				k = section + "." + k
			}
			out[k] = unquote(v)
		}
	}
	return out
}

func configChanges(base, head core.Snapshot) []core.Change {
	collect := func(s core.Snapshot) facts {
		fs := facts{}
		for _, f := range s.Files {
			if f.Content == nil || f.InLibrary() {
				continue
			}
			file := core.Unversioned(f.Chain)
			for k, v := range keyValues(f) {
				if keySizeKey.MatchString(k) {
					continue // reported under crypto
				}
				if secretKey.MatchString(k) {
					v = redact(v)
				}
				fs.add(file+"#"+k, v, f)
			}
		}
		return fs
	}
	return diff(core.Config, collect(base), collect(head), nil)
}

func redact(v string) string {
	sum := sha256.Sum256([]byte(v))
	return "<redacted:" + hex.EncodeToString(sum[:6]) + ">"
}

// properties parses java.util.Properties text format.
func properties(text string) map[string]string {
	out := map[string]string{}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimLeft(lines[i], " \t\f")
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		for continued(line) && i+1 < len(lines) {
			i++
			line = line[:len(line)-1] + strings.TrimLeft(lines[i], " \t\f")
		}
		k, v := splitProperty(line)
		out[k] = v
	}
	return out
}

// continued reports an odd number of trailing backslashes.
func continued(line string) bool {
	n := 0
	for i := len(line) - 1; i >= 0 && line[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
}

func splitProperty(line string) (string, string) {
	var key strings.Builder
	i := 0
	for ; i < len(line); i++ {
		c := line[i]
		if c == '\\' && i+1 < len(line) {
			i++
			key.WriteByte(unescape(line[i]))
			continue
		}
		if c == '=' || c == ':' || c == ' ' || c == '\t' || c == '\f' {
			break
		}
		key.WriteByte(c)
	}
	rest := strings.TrimLeft(line[i:], " \t\f")
	if rest != "" && (rest[0] == '=' || rest[0] == ':') {
		rest = strings.TrimLeft(rest[1:], " \t\f")
	}
	var val strings.Builder
	for j := 0; j < len(rest); j++ {
		if rest[j] == '\\' && j+1 < len(rest) {
			j++
			val.WriteByte(unescape(rest[j]))
			continue
		}
		val.WriteByte(rest[j])
	}
	return key.String(), val.String()
}

func unescape(c byte) byte {
	switch c {
	case 'n':
		return '\n'
	case 't':
		return '\t'
	case 'r':
		return '\r'
	}
	return c
}

// yamlKeys flattens every document to dotted keys; later documents are prefixed "#N.".
func yamlKeys(data []byte) map[string]string {
	out := map[string]string{}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	for doc := 0; ; doc++ {
		var n yaml.Node
		if err := dec.Decode(&n); err != nil {
			return out
		}
		prefix := ""
		if doc > 0 {
			prefix = fmt.Sprintf("#%d.", doc)
		}
		flattenYAML(&n, prefix, out)
	}
}

func flattenYAML(n *yaml.Node, key string, out map[string]string) {
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			flattenYAML(c, key, out)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			if key != "" && !strings.HasSuffix(key, ".") {
				k = key + "." + k
			} else {
				k = key + k
			}
			flattenYAML(n.Content[i+1], k, out)
		}
	case yaml.SequenceNode:
		for i, c := range n.Content {
			flattenYAML(c, fmt.Sprintf("%s[%d]", key, i), out)
		}
	case yaml.ScalarNode:
		out[key] = n.Value
	case yaml.AliasNode:
		// Recorded by name, never expanded: nested aliases grow exponentially.
		out[key] = "*" + n.Value
	}
}

// shellKeys reads VAR=value assignments; *_OPTS variables are split into JVM options.
func shellKeys(text string) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		m := shellAssig.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name, value := m[1], unquote(m[2])
		if strings.HasSuffix(name, "_OPTS") {
			for k, v := range jvmOptions(value) {
				out[k] = v
			}
			continue
		}
		out[name] = value
	}
	return out
}

func jvmOptions(value string) map[string]string {
	out := map[string]string{}
	for _, tok := range strings.Fields(value) {
		m := jvmOption.FindStringSubmatch(unquote(tok))
		switch {
		case m == nil:
		case m[1] != "":
			out[m[1]] = m[2]
		case m[3] != "":
			out[m[3]] = m[4]
		case m[7] != "":
			out["-XX:"+m[6]] = m[7]
		default:
			out["-XX:"+m[6]] = strings.TrimPrefix(m[5], "-XX:")
		}
	}
	return out
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// unitEnvironment reads systemd Environment= and EnvironmentFile= settings.
func unitEnvironment(text string) map[string]string {
	out := map[string]string{}
	for _, kv := range unitKeys(text) {
		switch kv[0] {
		case "Environment":
			for _, tok := range splitQuoted(kv[1]) {
				if k, v, ok := strings.Cut(tok, "="); ok {
					out[k] = v
				}
			}
		case "EnvironmentFile":
			out["EnvironmentFile"] = kv[1]
		}
	}
	return out
}

// splitQuoted splits on spaces outside double quotes and drops the quotes.
func splitQuoted(s string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
		case r == ' ' && !quoted:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
