// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func electLicense(path, text string) (string, error) {
	switch path {
	case "github.com/spdx/tools-golang":
		return "Apache-2.0", nil
	case "github.com/cyphar/filepath-securejoin":
		return "BSD-3-Clause", nil
	}
	lower := strings.ToLower(strings.Join(strings.Fields(text), " "))
	for _, rule := range []struct{ needle, id string }{
		{"mozilla public license", "MPL-2.0"},
		{"apache license", "Apache-2.0"},
		{"permission is hereby granted, free of charge", "MIT"},
		{"neither the name", "BSD-3-Clause"},
		{"redistribution and use in source and binary forms", "BSD-2-Clause"},
		{"permission to use, copy, modify, and/or distribute this software for any purpose", "ISC"},
		{"this is free and unencumbered software released into the public domain", "Unlicense"},
		{"zlib license", "Zlib"},
		{"this software is provided 'as-is'", "Zlib"},
		{"creative commons zero", "CC0-1.0"},
		{"cc0 1.0 universal", "CC0-1.0"},
		{"unicode license", "Unicode-3.0"},
		{"put into the public domain", "LicenseRef-Public-Domain"},
	} {
		if strings.Contains(lower, rule.needle) {
			return rule.id, nil
		}
	}
	return "", fmt.Errorf("unrecognized license for %s; review its license before distribution", path)
}

func moduleSourceURL(path, version string) string {
	parts := strings.Split(path, "/")
	if len(parts) >= 3 && parts[0] == "github.com" {
		path = strings.Join(parts[:3], "/")
	}
	if match := regexp.MustCompile(`[.-][0-9]{14}-([a-f0-9]+)$`).FindStringSubmatch(version); len(match) == 2 {
		version = match[1]
	}
	return "https://" + path + "/tree/" + version
}

func moduleNotice(path, version, dir string) (string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := strings.ToUpper(d.Name())
		if strings.HasPrefix(name, "LICENSE") || strings.HasPrefix(name, "COPYING") || strings.HasPrefix(name, "NOTICE") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Slice(files, func(i, j int) bool { return filepath.ToSlash(files[i]) < filepath.ToSlash(files[j]) })
	var primary strings.Builder
	for _, file := range files {
		if filepath.Dir(file) == dir && !strings.HasPrefix(strings.ToUpper(filepath.Base(file)), "NOTICE") {
			b, e := os.ReadFile(file)
			if e != nil {
				return "", e
			}
			primary.Write(b)
		}
	}
	if primary.Len() == 0 {
		readme := filepath.Join(dir, "README.md")
		data, e := os.ReadFile(readme)
		if e == nil && strings.Contains(strings.ToLower(string(data)), "license") {
			primary.Write(data)
			files = append(files, readme)
		}
	}
	license, err := electLicense(path, primary.String())
	if err != nil {
		return "", err
	}
	var out strings.Builder
	fmt.Fprintf(&out, "\n================================================================================\nModule: %s\nVersion: %s\nElected license: %s\n", path, version, license)
	if path == "github.com/spdx/tools-golang" || path == "github.com/cyphar/filepath-securejoin" {
		out.WriteString("Dual-license election recorded above. All upstream license texts follow.\n")
	}
	if license == "MPL-2.0" {
		fmt.Fprintf(&out, "MPL source: %s\n", moduleSourceURL(path, version))
	}
	for _, file := range files {
		rel, e := filepath.Rel(dir, file)
		if e != nil {
			return "", e
		}
		b, e := os.ReadFile(file)
		if e != nil {
			return "", e
		}
		fmt.Fprintf(&out, "\n--- %s ---\n", filepath.ToSlash(rel))
		out.Write(b)
		out.WriteString("\n--- end ---\n")
	}
	return out.String(), nil
}

func command(args ...string) ([]byte, error) {
	cmd := exec.Command("go", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go %s: %w: %s", strings.Join(args, " "), err, &stderr)
	}
	return b, nil
}

func generate(binaries []string) ([]byte, error) {
	modules := map[string]string{}
	for _, binary := range binaries {
		b, err := command("version", "-m", binary)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == "=>" {
				return nil, fmt.Errorf("replaced linked modules need an explicit license review")
			}
			if len(fields) >= 3 && fields[0] == "dep" {
				if old, ok := modules[fields[1]]; ok && old != fields[2] {
					return nil, fmt.Errorf("inconsistent module versions: %s", fields[1])
				}
				modules[fields[1]] = fields[2]
			}
		}
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("binary has no linked module information")
	}
	b, err := command("list", "-m", "-json", "all")
	if err != nil {
		return nil, err
	}
	dirs := map[string]string{}
	decoder := json.NewDecoder(bytes.NewReader(b))
	for {
		var m struct{ Path, Version, Dir string }
		err = decoder.Decode(&m)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		dirs[m.Path+"@"+m.Version] = m.Dir
	}
	keys := make([]string, 0, len(modules))
	for path := range modules {
		keys = append(keys, path)
	}
	sort.Strings(keys)
	var out strings.Builder
	out.WriteString("Generated by scripts/third-party-notices.sh from the release binaries' linked modules.\nDo not edit by hand; regenerate after changing dependencies.\n\nGo standard library license:\n")
	goRoot, err := command("env", "GOROOT")
	if err != nil {
		return nil, err
	}
	goLicense, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(goRoot)), "LICENSE"))
	if err != nil {
		return nil, err
	}
	out.Write(goLicense)
	for _, path := range keys {
		version := modules[path]
		dir := dirs[path+"@"+version]
		if dir == "" {
			return nil, fmt.Errorf("module cache source missing: %s@%s; run go mod download", path, version)
		}
		notice, e := moduleNotice(path, version, dir)
		if e != nil {
			return nil, e
		}
		out.WriteString(notice)
	}
	return []byte(out.String()), nil
}

func run() (err error) {
	check := flag.Bool("check", false, "Fail if THIRD_PARTY_NOTICES differs")
	output := flag.String("out", "THIRD_PARTY_NOTICES", "Generated notice path")
	flag.Parse()
	binaries := flag.Args()
	if len(binaries) == 0 {
		var dir string
		dir, err = os.MkdirTemp("", "packdiff-notices-")
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, os.RemoveAll(dir)) }()
		for _, target := range []string{"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64"} {
			parts := strings.Split(target, "/")
			binary := filepath.Join(dir, parts[0]+"-"+parts[1])
			cmd := exec.Command("go", "build", "-trimpath", "-o", binary, "./cmd/packdiff")
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+parts[0], "GOARCH="+parts[1])
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err = cmd.Run(); err != nil {
				return err
			}
			binaries = append(binaries, binary)
		}
	}
	data, err := generate(binaries)
	if err != nil {
		return err
	}
	if *check {
		existing, e := os.ReadFile(*output)
		if e != nil {
			return e
		}
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("%s drifted; run sh scripts/third-party-notices.sh", *output)
		}
		return nil
	}
	return os.WriteFile(*output, data, 0o644)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
