// SPDX-License-Identifier: Apache-2.0

// Command packdiff reports what changed between two release artifacts.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"sync"

	"github.com/jmurray2011/packdiff/artifact"
	"github.com/jmurray2011/packdiff/core"
	"github.com/jmurray2011/packdiff/detect"
	"github.com/jmurray2011/packdiff/report"
	"github.com/jmurray2011/packdiff/sbom"
)

// buildVersion is stamped at build time with -ldflags "-X main.buildVersion=...".
var buildVersion = "dev"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("packdiff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var firstParty list
	basePath := fs.String("base", "", "deployed artifact (RPM, DEB, WAR, JAR, tar.gz, zip)")
	headPath := fs.String("head", "", "candidate artifact")
	fs.Var(&firstParty, "first-party", "first-party package prefix, repeatable")
	outPath := fs.String("out", "", "JSON result path; - for stdout")
	htmlPath := fs.String("html", "", "HTML report path")
	format := fs.String("format", "summary", "terminal view: summary, full, none")
	rulesPath := fs.String("rules", "", "extra detector rules: suppressions and additional patterns")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	info, _ := debug.ReadBuildInfo()
	version, versionLine := versionDetails(buildVersion, info)
	if *showVersion {
		_, _ = fmt.Fprintln(stdout, versionLine)
		return 0
	}
	fail := func(err error) int {
		_, _ = fmt.Fprintln(stderr, "packdiff:", err)
		return 2
	}
	if *basePath == "" || *headPath == "" {
		return fail(errors.New("--base and --head are required"))
	}
	if !slices.Contains([]string{"summary", "full", "none"}, *format) {
		return fail(fmt.Errorf("unknown --format %q", *format))
	}
	var rules detect.Rules
	if *rulesPath != "" {
		data, err := os.ReadFile(*rulesPath)
		if err != nil {
			return fail(err)
		}
		if rules, err = detect.ParseRules(data); err != nil {
			return fail(fmt.Errorf("rules %s: %w", *rulesPath, err))
		}
	}

	ctx := context.Background()
	snaps := make([]core.Snapshot, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i, p := range []string{*basePath, *headPath} {
		wg.Go(func() { snaps[i], errs[i] = snapshot(ctx, p, firstParty) })
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return fail(err)
	}

	changes := detect.Run(snaps[0], snaps[1], detect.Options{FirstParty: firstParty, Rules: rules})
	r := core.Build(snaps[0].Artifact, snaps[1].Artifact, core.Options{FirstParty: firstParty}, changes)
	r.Tool.Version = version
	r.Tool.RulesDigest = rules.Digest()

	view := stdout
	if *outPath != "" {
		data, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return fail(err)
		}
		data = append(data, '\n')
		if *outPath == "-" {
			view = stderr
			_, err = stdout.Write(data)
		} else {
			err = os.WriteFile(*outPath, data, 0o644) //nolint:gosec // the result is meant to be shared
		}
		if err != nil {
			return fail(err)
		}
	}
	if *htmlPath != "" {
		var page bytes.Buffer
		if err := report.Write(&page, r); err != nil {
			return fail(err)
		}
		if err := os.WriteFile(*htmlPath, page.Bytes(), 0o644); err != nil { //nolint:gosec // the report is meant to be shared
			return fail(err)
		}
	}
	if err := r.WriteTerminal(view, *format); err != nil {
		return fail(err)
	}
	return 0
}

// snapshot walks one artifact and catalogs its components from a temporary extraction.
func snapshot(ctx context.Context, p string, firstParty []string) (s core.Snapshot, err error) {
	dir, err := os.MkdirTemp("", "packdiff-")
	if err != nil {
		return s, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(dir)) }()
	s, err = artifact.Open(ctx, p, artifact.Options{Want: detect.Wants(firstParty), ExtractTo: dir})
	if err != nil {
		return s, err
	}
	s.Components, err = sbom.Catalog(ctx, dir, filepath.Base(p))
	if err != nil {
		return s, fmt.Errorf("catalog %s: %w", filepath.Base(p), err)
	}
	return s, nil
}
