// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"go.yaml.in/yaml/v3"

	"github.com/jmurray2011/packdiff/core"
)

// ErrInvalidRules reports a rules file that cannot be applied.
var ErrInvalidRules = errors.New("invalid rules")

// Suppression silences changes whose subject matches.
type Suppression struct {
	Category core.Category `yaml:"category" json:"category"`
	Subject  string        `yaml:"subject" json:"subject"`
	Reason   string        `yaml:"reason" json:"reason"`
	re       *regexp.Regexp
}

// Pattern adds an outbound or crypto subject for each match in first-party literals and
// config values; the first capture group, when present, is the subject.
type Pattern struct {
	Category core.Category `yaml:"category" json:"category"`
	Match    string        `yaml:"match" json:"match"`
	Reason   string        `yaml:"reason" json:"reason"`
	re       *regexp.Regexp
}

// Rules are user-supplied suppressions and extra patterns; built-ins always apply.
type Rules struct {
	Suppress []Suppression `yaml:"suppress" json:"suppress"`
	Patterns []Pattern     `yaml:"patterns" json:"patterns"`
}

// builtin silences reference URIs that are never fetched at runtime, and build metadata.
var builtin = Rules{Suppress: []Suppression{
	{
		Category: core.Outbound, Reason: "built-in: XML namespace or schema URI",
		Subject: `^(\w[\w+.-]*://)?(www\.)?(w3\.org|xmlns\.jcp\.org|java\.sun\.com|jakarta\.ee|xmlns\.oracle\.com|springframework\.org|maven\.apache\.org|schemas\.xmlsoap\.org|schemas\.openxmlformats\.org|schemas\.microsoft\.com|purl\.org|ns\.adobe\.com|oasis-open\.org|docs\.oasis-open\.org|relaxng\.org|hibernate\.org|xml\.org|json-schema\.org|xmlpull\.org|jboss\.org|logback\.qos\.ch)(:\d+)?$`,
	},
	{
		Category: core.Outbound, Reason: "built-in: license or documentation link",
		Subject: `^(\w[\w+.-]*://)?(www\.)?(apache\.org|opensource\.org|gnu\.org|creativecommons\.org|eclipse\.org|docs\.oracle\.com|docs\.spring\.io|tools\.ietf\.org|datatracker\.ietf\.org|ietf\.org|rfc-editor\.org|wikipedia\.org|en\.wikipedia\.org|stackoverflow\.com|docs\.microsoft\.com|learn\.microsoft\.com)(:\d+)?$`,
	},
	{
		Category: core.Outbound, Reason: "built-in: loopback address",
		Subject: `^(\w[\w+.:-]*//)?(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(:\d+)?$`,
	},
	{
		Category: core.Config, Reason: "built-in: build metadata",
		Subject: `(^|[/!])(git|build-info)\.properties#`,
	},
}}

func init() {
	if err := builtin.compile(); err != nil {
		panic(err) // built-in rules are constants; a failure is a programming error
	}
}

// ParseRules reads a YAML rules file and validates it.
func ParseRules(data []byte) (Rules, error) {
	var r Rules
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&r); err != nil && !errors.Is(err, io.EOF) {
		return Rules{}, fmt.Errorf("%w: %w", ErrInvalidRules, err)
	}
	if err := r.compile(); err != nil {
		return Rules{}, err
	}
	return r, nil
}

func (r *Rules) compile() error {
	for i, s := range r.Suppress {
		if _, ok := core.ParseCategory(string(s.Category)); !ok {
			return fmt.Errorf("%w: suppress %d: unknown category %q", ErrInvalidRules, i, s.Category)
		}
		if s.Reason == "" {
			return fmt.Errorf("%w: suppress %d: reason is required", ErrInvalidRules, i)
		}
		re, err := regexp.Compile(s.Subject)
		if err != nil || s.Subject == "" {
			return fmt.Errorf("%w: suppress %d: subject: %v", ErrInvalidRules, i, err)
		}
		r.Suppress[i].re = re
	}
	for i, p := range r.Patterns {
		if p.Category != core.Outbound && p.Category != core.Crypto {
			return fmt.Errorf("%w: pattern %d: category must be outbound or crypto", ErrInvalidRules, i)
		}
		if p.Reason == "" {
			return fmt.Errorf("%w: pattern %d: reason is required", ErrInvalidRules, i)
		}
		re, err := regexp.Compile(p.Match)
		if err != nil || p.Match == "" {
			return fmt.Errorf("%w: pattern %d: match: %v", ErrInvalidRules, i, err)
		}
		r.Patterns[i].re = re
	}
	return nil
}

// Digest identifies the effective rule set (built-ins plus r) for the result header.
func (r Rules) Digest() string {
	data, _ := json.Marshal([]Rules{builtin, r}) // plain strings; cannot fail
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// suppress marks changes matched by built-in or user suppressions.
func (r Rules) suppress(cs []core.Change) {
	for i := range cs {
		for _, s := range append(builtin.Suppress[:len(builtin.Suppress):len(builtin.Suppress)], r.Suppress...) {
			if s.Category == cs[i].Category && s.re.MatchString(cs[i].Subject) {
				cs[i].Suppressed = s.Reason
				break
			}
		}
	}
}
