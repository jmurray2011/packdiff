// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"regexp"
	"strings"

	"github.com/jmurray2011/packdiff/core"
)

// componentKeys names components independently of version. Maven groups come, in order,
// from the jar's pom.properties; from the sole confirmed group for the artifact when the
// cataloger's guess extends it (a Bundle-SymbolicName such as "group.artifact"); or from the
// guess itself when it is plausible and identical across both releases. Otherwise the
// artifact is keyed alone so base and head still line up.
type componentKeys struct {
	confirmed map[string]string // artifactId -> sole pom.properties group
	guessed   map[string]string // artifactId -> sole plausible guess; "" when guesses disagree
}

var plausibleGroup = regexp.MustCompile(`^[a-z0-9_-]+(\.[a-z0-9_-]+)+$`)

func newComponentKeys(snaps ...core.Snapshot) componentKeys {
	confirmed, guessed := map[string]map[string]bool{}, map[string]map[string]bool{}
	note := func(m map[string]map[string]bool, a, g string) {
		if m[a] == nil {
			m[a] = map[string]bool{}
		}
		m[a][g] = true
	}
	for _, s := range snaps {
		for _, c := range s.Components {
			a, g, ok := mavenCoordinates(c)
			switch {
			case !ok:
			case c.Group != "":
				note(confirmed, a, c.Group)
			default:
				note(guessed, a, g)
			}
		}
	}
	sole := func(m map[string]map[string]bool, keep func(a, g string) bool) map[string]string {
		out := map[string]string{}
		for a, gs := range m {
			if len(gs) != 1 {
				continue
			}
			for g := range gs {
				if keep(a, g) {
					out[a] = g
				}
			}
		}
		return out
	}
	return componentKeys{
		confirmed: sole(confirmed, func(string, string) bool { return true }),
		// Guesses taken from class names carry capitals; bare-artifact guesses have no dot.
		guessed: sole(guessed, func(_, g string) bool { return plausibleGroup.MatchString(g) }),
	}
}

func (k componentKeys) key(c core.Component) string {
	a, g, ok := mavenCoordinates(c)
	cg := k.confirmed[a]
	switch {
	case !ok:
		return c.Type + "/" + c.Name
	case c.Group != "":
		return c.Group + ":" + a
	case cg != "" && (g == cg || strings.HasPrefix(g, cg+".")):
		return cg + ":" + a
	case k.guessed[a] != "":
		return k.guessed[a] + ":" + a
	}
	return a
}

// mavenCoordinates reads artifactId and group from a pkg:maven purl.
func mavenCoordinates(c core.Component) (artifact, group string, ok bool) {
	rest, ok := strings.CutPrefix(c.PURL, "pkg:maven/")
	if !ok {
		return "", "", false
	}
	rest, _, _ = strings.Cut(rest, "@")
	rest, _, _ = strings.Cut(rest, "?")
	group, artifact, ok = strings.Cut(rest, "/")
	return artifact, group, ok && artifact != ""
}

func depsChanges(base, head core.Snapshot, keys componentKeys) []core.Change {
	collect := func(s core.Snapshot) facts {
		fs := facts{}
		for _, c := range s.Components {
			key := keys.key(c)
			if cryptoLib(key) {
				continue // reported, with its version, under crypto
			}
			cur, ok := fs[key]
			if ok && cur.value != c.Version {
				cur.value = strings.Join(uniqueSorted(append(strings.Split(cur.value, ", "), c.Version)), ", ")
			} else {
				cur.value = c.Version
			}
			cur.locs = append(cur.locs, c.Location)
			fs[key] = cur
		}
		return fs
	}
	return diff(core.Deps, collect(base), collect(head), nil)
}
