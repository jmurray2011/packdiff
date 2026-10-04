// SPDX-License-Identifier: Apache-2.0

package core

import (
	"fmt"
	"io"
	"strings"
)

// WriteTerminal renders the human view: a counts line, then one line per change.
// format is "summary" (one line per change), "full" (adds details and locations), or "none".
func (r Result) WriteTerminal(w io.Writer, format string) error {
	if format == "none" {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s -> %s", r.Head.Name, r.Base.Version, r.Head.Version)
	for _, c := range Categories {
		n := r.Summary[c]
		var parts []string
		if n.Added > 0 {
			parts = append(parts, fmt.Sprintf("+%d", n.Added))
		}
		if n.Removed > 0 {
			parts = append(parts, fmt.Sprintf("-%d", n.Removed))
		}
		if n.Changed > 0 {
			parts = append(parts, fmt.Sprintf("~%d", n.Changed))
		}
		if len(parts) == 0 {
			parts = []string{"0"}
		}
		fmt.Fprintf(&b, " | %s %s", c, strings.Join(parts, " "))
	}
	b.WriteString("\n")

	for _, c := range r.Changes {
		fmt.Fprintf(&b, "%s %s %s", c.Category, c.Kind, oneLine(c.Subject))
		if c.Kind == Changed && c.Before != nil && c.After != nil && !strings.Contains(*c.Before+*c.After, "\n") {
			fmt.Fprintf(&b, "  (%s -> %s)", short(*c.Before), short(*c.After))
		}
		b.WriteString("\n")
		if format == "full" {
			for _, d := range c.Details {
				fmt.Fprintf(&b, "    %s\n", d)
			}
			for _, l := range c.Locations {
				fmt.Fprintf(&b, "    at %s\n", strings.Join(l.Chain, " > "))
			}
		}
	}
	if n := len(r.Suppressed); n > 0 {
		fmt.Fprintf(&b, "%d suppressed by rules\n", n)
	}
	if format == "full" {
		for _, c := range r.Suppressed {
			fmt.Fprintf(&b, "suppressed %s %s %s (%s)\n", c.Category, c.Kind, oneLine(c.Subject), c.Suppressed)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// short trims a sha256 value to 12 hex digits for reading; the JSON keeps it whole.
func short(v string) string {
	if rest, ok := strings.CutPrefix(v, "sha256:"); ok && len(rest) > 12 {
		return "sha256:" + rest[:12]
	}
	return v
}

func oneLine(s string) string { return strings.ReplaceAll(s, "\n", `\n`) }
