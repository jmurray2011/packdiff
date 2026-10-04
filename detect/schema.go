// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"regexp"
	"strings"

	"github.com/jmurray2011/packdiff/core"
)

var (
	liquibase    = regexp.MustCompile(`(?i)changelog.*\.(xml|ya?ml|json)$`)
	flywayV      = regexp.MustCompile(`^V\d[\w.]*__`)
	flywayR      = regexp.MustCompile(`^R__`)
	sqlComment   = regexp.MustCompile(`(?s)/\*.*?\*/|--[^\n]*`)
	ident        = `("[^"]+"|[\w$]+)(?:\.("[^"]+"|[\w$]+))?`
	createTable  = regexp.MustCompile(`(?i)^create\s+(?:(?:global\s+|local\s+)?(?:temporary|temp|unlogged)\s+)?table\s+(?:if\s+not\s+exists\s+)?` + ident)
	alterTable   = regexp.MustCompile(`(?i)^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?` + ident + `\s+(.*)$`)
	dropTable    = regexp.MustCompile(`(?i)^drop\s+table\s+(?:if\s+exists\s+)?(.+?)(?:\s+(?:cascade|restrict))?$`)
	createExt    = regexp.MustCompile(`(?i)^create\s+extension\s+(?:if\s+not\s+exists\s+)?("[^"]+"|[\w-]+)`)
	grant        = regexp.MustCompile(`(?i)^grant\s+(.+?)\s+on\s+(?:table\s+)?` + ident + `\s+to\s+(.+)$`)
	createIndex  = regexp.MustCompile(`(?i)^create\s+(?:unique\s+)?index\s+(?:concurrently\s+)?(?:if\s+not\s+exists\s+)?("[^"]+"|[\w$]+)?\s*on\s+(?:only\s+)?` + ident)
	alterAction  = regexp.MustCompile(`(?i)^(add|drop|alter|rename)\s+(?:(column|constraint)\s+)?(?:if\s+(?:not\s+)?exists\s+)?("[^"]+"|[\w$]+)`)
	whitespaceRE = regexp.MustCompile(`\s+`)
)

func isSchemaFile(f core.File) bool {
	name := f.Name()
	return strings.HasSuffix(strings.ToLower(name), ".sql") || liquibase.MatchString(name)
}

func schemaChanges(base, head core.Snapshot) []core.Change {
	collect := func(s core.Snapshot) facts {
		fs := facts{}
		for _, f := range s.Files {
			if f.InLibrary() || !isSchemaFile(f) {
				continue
			}
			subject := core.Unversioned(f.Chain)
			fs.add(subject, "sha256:"+f.SHA256, f)
			if f.Content != nil && strings.HasSuffix(strings.ToLower(f.Name()), ".sql") {
				cur := fs[subject]
				cur.details = summarizeSQL(string(f.Content))
				fs[subject] = cur
			}
		}
		return fs
	}
	why := func(subject string, _, _ fact) []string {
		name := subject[strings.LastIndexAny(subject, "/!")+1:]
		switch {
		case flywayV.MatchString(name):
			return []string{"applied migration modified: checksum validation fails on databases that ran the old version"}
		case flywayR.MatchString(name):
			return []string{"repeatable migration changed: it re-runs on next deploy"}
		}
		return []string{"migration modified"}
	}
	return diff(core.Schema, collect(base), collect(head), why)
}

// summarizeSQL lists the schema-affecting statements, sorted and de-duplicated.
func summarizeSQL(sql string) []string {
	var out []string
	for _, stmt := range strings.Split(sqlComment.ReplaceAllString(sql, " "), ";") {
		stmt = strings.TrimSpace(whitespaceRE.ReplaceAllString(stmt, " "))
		if m := createTable.FindStringSubmatch(stmt); m != nil {
			out = append(out, "create table "+name(m[1], m[2]))
		} else if m := alterTable.FindStringSubmatch(stmt); m != nil {
			for _, action := range splitTopLevel(m[3]) {
				if a := alterAction.FindStringSubmatch(strings.TrimSpace(action)); a != nil {
					kind := strings.ToLower(a[2])
					if kind == "" {
						kind = "column"
					}
					out = append(out, "alter table "+name(m[1], m[2])+": "+strings.ToLower(a[1])+" "+kind+" "+unq(a[3]))
				}
			}
		} else if m := dropTable.FindStringSubmatch(stmt); m != nil {
			for _, t := range strings.Split(m[1], ",") {
				out = append(out, "drop table "+unq(strings.TrimSpace(t)))
			}
		} else if m := createExt.FindStringSubmatch(stmt); m != nil {
			out = append(out, "create extension "+unq(m[1]))
		} else if m := grant.FindStringSubmatch(stmt); m != nil {
			out = append(out, "grant "+strings.ToLower(m[1])+" on "+name(m[2], m[3])+" to "+unq(m[4]))
		} else if m := createIndex.FindStringSubmatch(stmt); m != nil {
			out = append(out, "create index "+unq(m[1])+" on "+name(m[2], m[3]))
		}
	}
	if len(out) == 0 {
		return nil
	}
	return uniqueSorted(out)
}

func name(a, b string) string {
	if b == "" {
		return unq(a)
	}
	return unq(a) + "." + unq(b)
}

func unq(s string) string { return strings.Trim(s, `"`) }

// splitTopLevel splits on commas outside parentheses.
func splitTopLevel(s string) []string {
	var out []string
	depth, start := 0, 0
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}
