// SPDX-License-Identifier: Apache-2.0

// Package detect turns two artifact snapshots into categorized changes. It is pure.
package detect

import (
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/jmurray2011/packdiff/core"
)

// Options tunes detection.
type Options struct {
	// FirstParty are package prefixes whose classes are scanned for literals.
	FirstParty []string
	Rules      Rules
}

// Run applies every detector to base and head and marks changes silenced by rules.
func Run(base, head core.Snapshot, opts Options) []core.Change {
	bl, hl := literals(base, opts.FirstParty), literals(head, opts.FirstParty)
	keys := newComponentKeys(base, head)
	var out []core.Change
	out = append(out, configChanges(base, head)...)
	out = append(out, diff(core.Config, placeholderFacts(base, bl), placeholderFacts(head, hl), nil)...)
	out = append(out, diff(core.Outbound, outboundFacts(base, bl, opts.Rules, keys), outboundFacts(head, hl, opts.Rules, keys), nil)...)
	out = append(out, diff(core.Crypto, cryptoFacts(base, bl, opts.Rules, keys), cryptoFacts(head, hl, opts.Rules, keys), nil)...)
	out = append(out, schemaChanges(base, head)...)
	out = append(out, hostChanges(base, head)...)
	out = append(out, depsChanges(base, head, keys)...)
	out = append(out, filesChanges(base, head, covered(out))...)
	opts.Rules.suppress(out)
	suppressStamps(out, base.Artifact, head.Artifact)
	return out
}

// Wants selects the entries whose content detectors read: first-party classes anywhere,
// and config, schema, and server files outside libraries.
func Wants(firstParty []string) core.Wants {
	return func(chain []string) bool {
		if firstPartyClass(chain, firstParty) {
			return true
		}
		f := core.File{Chain: chain}
		if f.InLibrary() {
			return false
		}
		name := f.Name()
		return isConfigFile(f) || isSchemaFile(f) || name == "server.xml" || isUnit(name) || isSecurityConfig(name) || isSourceMap(name)
	}
}

// fact is one observed value with where it was seen.
type fact struct {
	value   string
	locs    []core.Location
	details []string
}

// facts maps a change subject to what one snapshot says about it.
type facts map[string]fact

func (fs facts) add(subject, value string, f core.File) {
	cur, ok := fs[subject]
	if ok && cur.value != value {
		value = strings.Join(uniqueSorted(append(strings.Split(cur.value, "\n"), value)), "\n")
	}
	cur.value = value
	cur.locs = append(cur.locs, f.Location())
	fs[subject] = cur
}

// explain adds details to a changed subject.
type explain func(subject string, before, after fact) []string

// diff compares two fact sets; changed facts locate in head, removed ones in base.
func diff(cat core.Category, base, head facts, why explain) []core.Change {
	var out []core.Change
	for _, s := range slices.Sorted(maps.Keys(head)) {
		h := head[s]
		b, ok := base[s]
		switch {
		case !ok:
			out = append(out, core.Change{Category: cat, Kind: core.Added, Subject: s, After: ptr(h.value), Details: h.details, Locations: h.locs})
		case b.value != h.value:
			c := core.Change{Category: cat, Kind: core.Changed, Subject: s, Before: ptr(b.value), After: ptr(h.value), Locations: h.locs}
			if why != nil {
				c.Details = why(s, b, h)
			}
			out = append(out, c)
		}
	}
	for _, s := range slices.Sorted(maps.Keys(base)) {
		if _, ok := head[s]; !ok {
			b := base[s]
			out = append(out, core.Change{Category: cat, Kind: core.Removed, Subject: s, Before: ptr(b.value), Details: b.details, Locations: b.locs})
		}
	}
	return out
}

func ptr(s string) *string { return &s }

func uniqueSorted(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

// payload reports whether f sits directly in the artifact payload rather than in a nested archive.
func payload(f core.File) bool { return len(f.Chain) == 2 }

func isUnit(name string) bool {
	switch path.Ext(name) {
	case ".service", ".socket", ".timer":
		return true
	}
	return false
}
