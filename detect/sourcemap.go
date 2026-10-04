// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"encoding/json"
	"strings"

	"github.com/jmurray2011/packdiff/core"
)

func isSourceMap(name string) bool {
	return strings.HasSuffix(name, ".js.map") || strings.HasSuffix(name, ".mjs.map") || strings.HasSuffix(name, ".cjs.map")
}

// sourceMapLiterals returns the string literals in a source map's embedded first-party
// sources. Sources under node_modules, the bundler's own runtime, and externals are
// skipped. Each literal's location ends in the original source path.
func sourceMapLiterals(f *core.File) []literal {
	var m struct {
		Sources        []string  `json:"sources"`
		SourcesContent []*string `json:"sourcesContent"`
	}
	if json.Unmarshal(f.Content, &m) != nil {
		return nil // not a usable source map; the file itself is still compared
	}
	var out []literal
	for i, src := range m.Sources {
		name := sourcePath(src)
		if i >= len(m.SourcesContent) || m.SourcesContent[i] == nil || !firstPartySource(src) || strings.HasPrefix(name, "../") {
			continue // "../" sources sit outside the project root: vendored copies, not first-party code
		}
		chain := make([]string, len(f.Chain), len(f.Chain)+1)
		copy(chain, f.Chain)
		at := &core.File{Chain: append(chain, name)}
		for _, s := range jsStrings(*m.SourcesContent[i]) {
			out = append(out, literal{s, at})
		}
	}
	return out
}

func firstPartySource(src string) bool {
	return !strings.Contains(src, "node_modules/") && !strings.Contains(src, "webpack/bootstrap") &&
		!strings.Contains(src, "webpack/runtime") && !strings.Contains(src, "/external ") && !strings.HasPrefix(src, "external ")
}

// sourcePath strips the bundler's scheme and project prefix: "webpack://app/./src/a.ts" is "src/a.ts".
func sourcePath(src string) string {
	if _, rest, ok := strings.Cut(src, "://"); ok {
		if _, p, ok := strings.Cut(rest, "/"); ok {
			src = p
		}
	}
	return strings.TrimPrefix(strings.TrimLeft(src, "/"), "./")
}

// jsStrings returns the contents of quoted string and template literals in JavaScript or
// TypeScript source, skipping comments. It is a lexer, not a parser: a regular expression
// literal containing a quote can split a string early, which costs at most a missed literal.
func jsStrings(src string) []string {
	var out []string
	for i := 0; i < len(src); i++ {
		switch c := src[i]; {
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			if j := strings.IndexByte(src[i:], '\n'); j >= 0 {
				i += j
			} else {
				i = len(src)
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			if j := strings.Index(src[i+2:], "*/"); j >= 0 {
				i += j + 3
			} else {
				i = len(src)
			}
		case c == '"' || c == '\'' || c == '`':
			var b strings.Builder
			j := i + 1
			for ; j < len(src) && src[j] != c; j++ {
				if src[j] == '\\' && j+1 < len(src) {
					j++
				}
				if c != '`' && src[j] == '\n' {
					break // unterminated quote on this line
				}
				b.WriteByte(src[j])
			}
			if b.Len() > 0 {
				out = append(out, b.String())
			}
			i = j
		}
	}
	return out
}
