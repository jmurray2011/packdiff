// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"strings"
	"testing"

	"github.com/jmurray2011/packdiff/core"
)

// FuzzParsers runs every text parser over arbitrary input. They must not panic.
func FuzzParsers(f *testing.F) {
	for _, s := range []string{
		"a=1\nb : 2\nmulti=x \\\n  y\n# c\n",
		"server:\n  port: 8080\nlist: [a, b]\nx: &x {k: v}\ny: *x\n",
		"export JAVA_OPTS=\"-Xmx2g -Dk=v -XX:+UseG1GC\"\nA='b'\n",
		"[Service]\nUser=app\nEnvironment=\"A=1\" B=2\nExecStart=/bin/app --port=8080\n",
		`<Server port="8005"><Connector port="8443" protocol="HTTP/1.1" SSLEnabled="true"/></Server>`,
		"create table a (id int); alter table a add column b text, drop column c; /* x */ grant select on a to r;",
		"${k:#{1}} jdbc:postgresql://db.example.net:5432/x https://api.example.net/p",
		"const a = 'x\\'y'; /* \"no\" */ // 'c'\nlet t = `a${b}c`",
		`{"version":3,"sources":["webpack://a/./src/x.ts","webpack://a/./node_modules/l/i.js"],"sourcesContent":["const u = \"https://api.example.net\"",null]}`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		properties(s)
		yamlKeys([]byte(s))
		shellKeys(s)
		unitEnvironment(s)
		unitKeys(s)
		tomcatPorts([]byte(s))
		summarizeSQL(s)
		jsStrings(s)
		sourceMapLiterals(&core.File{Chain: []string{"a.rpm", "x.js.map"}, Content: []byte(s)})
		lineDiff(strings.Split(s, "\n"), strings.Split(strings.ToUpper(s), "\n"))
		for _, m := range urlRE.FindAllString(s, -1) {
			origin(m)
		}
		for _, m := range jdbcRE.FindAllString(s, -1) {
			jdbcOrigin(m)
		}
		snap := core.Snapshot{Files: []core.File{{Chain: []string{"a.rpm", "opt/app/com/example/A.class"}, Content: []byte(s)}}}
		literals(snap, []string{"com.example"})
	})
}
