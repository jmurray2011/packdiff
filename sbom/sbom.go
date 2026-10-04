// SPDX-License-Identifier: Apache-2.0

// Package sbom catalogs third-party components in an extracted payload with Syft.
package sbom

import (
	"context"
	"errors"
	"path"
	"strings"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/pkg"
	_ "modernc.org/sqlite" // pure-Go driver syft needs for RPM databases

	"github.com/jmurray2011/packdiff/core"
)

// Catalog lists the components under root; outer names the artifact the files came from.
func Catalog(ctx context.Context, root, outer string) (out []core.Component, err error) {
	src, err := syft.GetSource(ctx, root, syft.DefaultGetSourceConfig().WithSources("local-directory"))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, src.Close()) }()
	cfg := syft.DefaultCreateSBOMConfig().WithCatalogerSelection(cataloging.NewSelectionRequest().WithAdditions("sbom-cataloger"))
	bom, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return nil, err
	}
	for _, p := range bom.Artifacts.Packages.Sorted() {
		out = append(out, core.Component{
			Type:     string(p.Type),
			Name:     p.Name,
			Version:  p.Version,
			PURL:     p.PURL,
			Group:    group(p),
			Location: core.Location{Chain: chain(outer, p)},
		})
	}
	return out, ctx.Err()
}

// chain maps a package's evidence to an archive chain; Java virtual paths delimit nested jars with ':'.
func chain(outer string, p pkg.Package) []string {
	if m, ok := p.Metadata.(pkg.JavaArchive); ok && m.VirtualPath != "" {
		parts := strings.Split(m.VirtualPath, ":")
		out := []string{outer, strings.TrimPrefix(parts[0], "/")}
		// Shaded entries end in Maven "group:artifact", which is not a chain link.
		for _, p := range parts[1:] {
			if !strings.Contains(p, "/") && !isArchive(p) {
				break
			}
			out = append(out, p)
		}
		return out
	}
	if locs := p.Locations.ToSlice(); len(locs) > 0 {
		return []string{outer, strings.TrimPrefix(locs[0].RealPath, "/")}
	}
	return []string{outer}
}

// group returns the Maven groupId only when pom.properties declared it. Without one, Syft
// derives a group from manifest headers or class names, which shifts between releases.
func group(p pkg.Package) string {
	if m, ok := p.Metadata.(pkg.JavaArchive); ok && m.PomProperties != nil {
		return m.PomProperties.GroupID
	}
	return ""
}

func isArchive(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".jar", ".war", ".ear", ".zip":
		return true
	}
	return false
}
