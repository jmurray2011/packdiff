// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	_ "modernc.org/sqlite"
)

func releaseNotes(text, tag string) (string, error) {
	if !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`).MatchString(tag) {
		return "", fmt.Errorf("invalid release tag %q", tag)
	}
	heading := "## [" + strings.TrimPrefix(tag, "v") + "]"
	var lines []string
	found := false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "## ") {
			if found {
				break
			}
			if line == heading || strings.HasPrefix(line, heading+" - ") {
				found = true
			}
			continue
		}
		if found {
			lines = append(lines, line)
		}
	}
	notes := strings.TrimSpace(strings.Join(lines, "\n"))
	if !found || notes == "" {
		return "", fmt.Errorf("CHANGELOG has no nonempty section for %s", tag)
	}
	return notes + "\n", nil
}

func binarySBOM(ctx context.Context, path string) (data []byte, err error) {
	source, err := syft.GetSource(ctx, path, syft.DefaultGetSourceConfig().WithSources("local-file"))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	bom, err := syft.CreateSBOM(ctx, source, syft.DefaultCreateSBOMConfig().WithTool("packdiff-release", "dev"))
	if err != nil {
		return nil, err
	}
	encoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.EncoderConfig{Version: "1.6", Pretty: true})
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err = encoder.Encode(&out, *bom); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func run(args []string) error {
	if len(args) == 2 && args[0] == "notes" {
		b, err := os.ReadFile("CHANGELOG.md")
		if err != nil {
			return err
		}
		notes, err := releaseNotes(string(b), args[1])
		if err != nil {
			return err
		}
		_, err = fmt.Print(notes)
		return err
	}
	if len(args) == 3 && args[0] == "sbom" {
		b, err := binarySBOM(context.Background(), args[1])
		if err != nil {
			return err
		}
		return os.WriteFile(args[2], b, 0o644)
	}
	return fmt.Errorf("usage: release notes <tag> | release sbom <binary> <output.cdx.json>")
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
