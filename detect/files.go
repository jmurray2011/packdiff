// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/jmurray2011/packdiff/core"
)

// rollUpOver is how many same-kind file changes one directory may hold before they are
// reported as a single change.
const rollUpOver = 20

// covered returns the payload files that other categories already report a change in.
// Attribute-only host changes do not count: they say nothing about content.
func covered(cs []core.Change) map[string]bool {
	out := map[string]bool{}
	for _, c := range cs {
		if c.Category == core.Host && (strings.HasPrefix(c.Subject, "file:") || strings.HasPrefix(c.Subject, "files:")) {
			continue
		}
		for _, l := range c.Locations {
			if len(l.Chain) >= 2 {
				out[core.Unversioned(l.Chain[:2])] = true
			}
		}
	}
	return out
}

// filesChanges reports payload files added, removed, or with new content, except those
// another category already explains. Nested archive entries are not listed; the archive
// itself is. Changes are rolled up three ways: files added or removed with their whole
// directory tree become one "dir/**" change; recompiled classes under a classes root
// become one "root/**/*.class" change; and more than rollUpOver same-kind changes in one
// directory become one "dir/*" change.
func filesChanges(base, head core.Snapshot, skip map[string]bool) []core.Change {
	collect := func(s core.Snapshot) (facts, map[string]bool) {
		fs, dirs := facts{}, map[string]bool{}
		for _, f := range s.Files {
			if !payload(f) || f.Mode&0o170000 != 0o100000 {
				continue
			}
			key := core.Unversioned(f.Chain)
			fs.add(key, "sha256:"+f.SHA256, f)
			for d := path.Dir(key); d != "." && !dirs[d]; d = path.Dir(d) {
				dirs[d] = true
			}
		}
		return fs, dirs
	}
	bf, bdirs := collect(base)
	hf, hdirs := collect(head)

	type group struct{ kind, subject string }
	groups := map[group][]core.Change{}
	for _, c := range diff(core.Files, bf, hf, nil) {
		if skip[c.Subject] {
			continue
		}
		g := group{string(c.Kind), path.Dir(c.Subject) + "/*"}
		if tree := newTree(c, bdirs, hdirs); tree != "" {
			g.subject = tree + "/**"
		} else if i := strings.Index(c.Subject, "/classes/"); i >= 0 && strings.HasSuffix(c.Subject, ".class") {
			g.subject = c.Subject[:i+len("/classes/")] + "**/*.class"
		}
		groups[g] = append(groups[g], c)
	}

	var out []core.Change
	for _, g := range slices.SortedFunc(maps.Keys(groups), func(a, b group) int {
		return strings.Compare(a.subject+"\x00"+a.kind, b.subject+"\x00"+b.kind)
	}) {
		cs := groups[g]
		limit := 1 // trees and classes roll up from two changes
		if strings.HasSuffix(g.subject, "/*") && !strings.HasSuffix(g.subject, "**/*") {
			limit = rollUpOver
		}
		if len(cs) <= limit {
			out = append(out, cs...)
			continue
		}
		r := core.Change{Category: core.Files, Kind: cs[0].Kind, Subject: g.subject, Details: []string{fmt.Sprintf("%d files", len(cs))}}
		for _, c := range cs {
			r.Details = append(r.Details, c.Subject)
			r.Locations = append(r.Locations, c.Locations...)
		}
		out = append(out, r)
	}
	return out
}

// newTree returns the highest directory of an added (or removed) file that does not exist
// in the other release, or "" when the file's directories exist on both sides.
func newTree(c core.Change, baseDirs, headDirs map[string]bool) string {
	var other map[string]bool
	switch c.Kind {
	case core.Added:
		other = baseDirs
	case core.Removed:
		other = headDirs
	default:
		return ""
	}
	parts := strings.Split(c.Subject, "/")
	for i := 1; i < len(parts); i++ {
		if d := strings.Join(parts[:i], "/"); !other[d] {
			return d
		}
	}
	return ""
}
