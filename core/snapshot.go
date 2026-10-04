// SPDX-License-Identifier: Apache-2.0

package core

import (
	"path"
	"strings"
)

// File is one entry found while walking an artifact, at any archive depth.
type File struct {
	// Chain runs from the outer artifact name to the entry; nested archives are chain links.
	Chain  []string
	Mode   uint32 // unix st_mode bits, including type
	User   string
	Group  string
	Size   int64
	SHA256 string
	Config bool   // package marks the file as config
	Caps   string // file capabilities, when the package records them
	Link   string
	// Content is set only for entries the capture policy asked for.
	Content []byte
}

// Key identifies the entry independently of the outer artifact name.
func (f File) Key() string { return strings.Join(f.Chain[1:], "!") }

// Name is the base name of the innermost path.
func (f File) Name() string { return path.Base(f.Chain[len(f.Chain)-1]) }

// InLibrary reports whether the entry sits inside a jar, i.e. in library code.
func (f File) InLibrary() bool {
	for _, p := range f.Chain[1 : len(f.Chain)-1] {
		if strings.HasSuffix(p, ".jar") {
			return true
		}
	}
	return false
}

// Location returns the entry's location for a change.
func (f File) Location() Location { return Location{Chain: f.Chain} }

// Package is install metadata from RPM or DEB headers.
type Package struct {
	Scripts  map[string]string // phase -> body, e.g. "preinstall"
	Requires []string
	Provides []string
}

// Snapshot is everything a detector may look at for one artifact.
type Snapshot struct {
	Artifact   Artifact
	Package    Package
	Files      []File
	Components []Component
}

// Wants decides which entries keep their content in a snapshot.
type Wants func(chain []string) bool

// Component is one third-party package found in an artifact.
type Component struct {
	Type    string
	Name    string
	Version string
	// Group is the Maven groupId from pom.properties; empty when the cataloger had to guess.
	Group    string
	PURL     string
	Location Location
}
