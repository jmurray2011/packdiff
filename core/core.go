// SPDX-License-Identifier: Apache-2.0

// Package core holds the change model and summary. It is pure:
// no I/O beyond writing a rendered view to a caller-supplied writer.
package core

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"slices"
	"strings"
)

// SchemaVersion is the version of the JSON result layout.
const SchemaVersion = 1

// Category groups changes by the question a change board asks.
type Category string

// Categories in output order.
const (
	Config   Category = "config"
	Outbound Category = "outbound"
	Crypto   Category = "crypto"
	Schema   Category = "schema"
	Host     Category = "host"
	Deps     Category = "deps"
	Files    Category = "files"
)

// Categories lists every category in output order.
var Categories = []Category{Config, Outbound, Crypto, Schema, Host, Deps, Files}

// ParseCategory validates a category name.
func ParseCategory(s string) (Category, bool) {
	c := Category(s)
	return c, slices.Contains(Categories, c)
}

// Kind is the direction of a change.
type Kind string

// Change kinds.
const (
	Added   Kind = "added"
	Removed Kind = "removed"
	Changed Kind = "changed"
)

// Location is the archive chain from the outer artifact to the file holding the evidence.
type Location struct {
	Chain []string `json:"chain"`
}

// Change is one difference between base and head.
type Change struct {
	ID        string     `json:"id"`
	Category  Category   `json:"category"`
	Kind      Kind       `json:"kind"`
	Subject   string     `json:"subject"`
	Before    *string    `json:"before"`
	After     *string    `json:"after"`
	Details   []string   `json:"details,omitempty"`
	Locations []Location `json:"locations"`
	// Suppressed holds the reason of the rule that silenced the change, if any.
	Suppressed string `json:"suppressed,omitempty"`
}

var versionSegment = regexp.MustCompile(`[-_.]?v?\d+(\.\d+)*([-.][A-Za-z0-9]+)*(\.(jar|war|ear|zip|rpm|deb|tar\.gz|tgz|tar\.xz|txz|tar\.zst|tzst|tar\.bz2|tbz2|tar))$`)

// versionedDir matches a directory named for a release, such as "apache-tomcat-10.1.30" or
// "kafka_2.13-3.7.0": a dotted version after "-" or "_", with optional suffixes.
var versionedDir = regexp.MustCompile(`^(.+?)[-_]v?\d+(?:\.\d+)+[0-9A-Za-z]*(?:[-.+~][0-9A-Za-z]+)*$`)

// Unversioned joins chain[1:] with "!", dropping the outer artifact and the versions in
// archive and directory names, so the same entry keys alike in base and head.
func Unversioned(chain []string) string {
	if len(chain) < 2 {
		return ""
	}
	parts := make([]string, 0, len(chain)-1)
	for _, p := range chain[1:] {
		dirs := strings.Split(p, "/")
		last := len(dirs) - 1
		for i := range dirs[:last] {
			if m := versionedDir.FindStringSubmatch(dirs[i]); m != nil {
				dirs[i] = m[1]
			}
		}
		dirs[last] = versionSegment.ReplaceAllString(dirs[last], "$3")
		parts = append(parts, strings.Join(dirs, "/"))
	}
	return strings.Join(parts, "!")
}

func locationClass(locs []Location) string {
	if len(locs) == 0 {
		return ""
	}
	return Unversioned(locs[0].Chain)
}

// StableID hashes category, subject, and location class so runs can be joined.
func (c Change) StableID() string {
	sum := sha256.Sum256([]byte(string(c.Category) + "\x00" + c.Subject + "\x00" + locationClass(c.Locations)))
	return string(c.Category) + ":" + hex.EncodeToString(sum[:8])
}

// Artifact identifies one input.
type Artifact struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Options records the run options that shape the result.
type Options struct {
	FirstParty []string `json:"first_party"`
}

// Tool identifies the producing tool.
type Tool struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	RulesDigest string `json:"rules_digest,omitempty"`
}

// Counts summarizes one category.
type Counts struct {
	Added      int `json:"added"`
	Removed    int `json:"removed"`
	Changed    int `json:"changed"`
	Suppressed int `json:"suppressed"`
}

// Result is the full run output.
type Result struct {
	SchemaVersion int                 `json:"schema_version"`
	Tool          Tool                `json:"tool"`
	Base          Artifact            `json:"base"`
	Head          Artifact            `json:"head"`
	Options       Options             `json:"options"`
	Summary       map[Category]Counts `json:"summary"`
	Changes       []Change            `json:"changes"`
	Suppressed    []Change            `json:"suppressed"`
}

// Build assembles a deterministic result: changes get IDs and are sorted, and changes
// silenced by rules move to Suppressed.
func Build(base, head Artifact, opts Options, changes []Change) Result {
	out := make([]Change, len(changes))
	copy(out, changes)
	for i := range out {
		out[i].ID = out[i].StableID()
		slices.SortFunc(out[i].Locations, func(a, b Location) int {
			return strings.Compare(strings.Join(a.Chain, "\x00"), strings.Join(b.Chain, "\x00"))
		})
	}
	rank := func(c Category) int { return slices.Index(Categories, c) }
	slices.SortFunc(out, func(a, b Change) int {
		if d := rank(a.Category) - rank(b.Category); d != 0 {
			return d
		}
		if d := strings.Compare(a.Subject, b.Subject); d != 0 {
			return d
		}
		if d := strings.Compare(string(a.Kind), string(b.Kind)); d != 0 {
			return d
		}
		return strings.Compare(a.ID, b.ID)
	})

	suppressed := []Change{}
	kept := out[:0:0]
	for _, c := range out {
		if c.Suppressed != "" {
			suppressed = append(suppressed, c)
		} else {
			kept = append(kept, c)
		}
	}
	out = kept

	r := Result{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Name: "packdiff"},
		Base:          base,
		Head:          head,
		Options:       opts,
		Summary:       map[Category]Counts{},
		Changes:       out,
		Suppressed:    suppressed,
	}
	if r.Options.FirstParty == nil {
		r.Options.FirstParty = []string{}
	}
	for _, c := range Categories {
		r.Summary[c] = Counts{}
	}
	for _, c := range suppressed {
		n := r.Summary[c.Category]
		n.Suppressed++
		r.Summary[c.Category] = n
	}
	for _, c := range out {
		n := r.Summary[c.Category]
		switch c.Kind {
		case Added:
			n.Added++
		case Removed:
			n.Removed++
		case Changed:
			n.Changed++
		}
		r.Summary[c.Category] = n
	}
	return r
}
