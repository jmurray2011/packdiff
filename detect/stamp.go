// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"strings"

	"github.com/jmurray2011/packdiff/core"
)

const stampReason = "built-in: release version"

// versionPairs returns (base, head) spellings of the release version to substitute: the
// full version and the upstream part without epoch or package release. Versions too short
// to be specific, such as "1", are skipped.
func versionPairs(base, head string) [][2]string {
	upstream := func(v string) string {
		if _, rest, ok := strings.Cut(v, ":"); ok {
			v = rest
		}
		if i := strings.LastIndex(v, "-"); i > 0 {
			v = v[:i]
		}
		return v
	}
	var out [][2]string
	for _, p := range [][2]string{{base, head}, {upstream(base), upstream(head)}} {
		if p[0] != p[1] && strings.Contains(p[0], ".") && len(p[0]) >= 3 && len(p[1]) >= 3 {
			out = append(out, p)
		}
	}
	return out
}

// stamped reports whether after is before with the release version moved forward.
func stamped(before, after string, pairs [][2]string) bool {
	for _, p := range pairs {
		if strings.Contains(before, p[0]) && strings.ReplaceAll(before, p[0], p[1]) == after {
			return true
		}
	}
	return false
}

// suppressStamps marks changes that only move the release version: a changed value, or a
// removed and added subject pair, that differ by nothing but the version. Dependency
// changes are left alone, since a library can share the release's version by coincidence.
func suppressStamps(cs []core.Change, base, head core.Artifact) {
	pairs := versionPairs(base.Version, head.Version)
	if len(pairs) == 0 {
		return
	}
	added := map[string]int{}
	for i, c := range cs {
		if c.Kind == core.Added {
			added[string(c.Category)+"\x00"+c.Subject] = i
		}
	}
	for i := range cs {
		c := &cs[i]
		if c.Category == core.Deps || c.Suppressed != "" {
			continue
		}
		switch c.Kind {
		case core.Changed:
			if c.Before != nil && c.After != nil && stamped(*c.Before, *c.After, pairs) {
				c.Suppressed = stampReason
			}
		case core.Removed:
			for _, p := range pairs {
				if !strings.Contains(c.Subject, p[0]) {
					continue
				}
				if j, ok := added[string(c.Category)+"\x00"+strings.ReplaceAll(c.Subject, p[0], p[1])]; ok {
					c.Suppressed, cs[j].Suppressed = stampReason, stampReason
					break
				}
			}
		}
	}
}
