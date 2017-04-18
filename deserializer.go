package httpseverywhere

import (
	"bytes"
	"encoding/gob"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/armon/go-radix"
	"github.com/getlantern/golog"
)

type deserializer struct {
	log golog.Logger
}

func newDeserializer() *deserializer {
	return &deserializer{
		log: golog.LoggerFor("httpseverywhere-deserializer"),
	}
}

func (d *deserializer) newRulesets() (map[string]*ruleset, *radix.Tree, error) {
	start := time.Now()
	data := MustAsset("rulesets.gob")
	buf := bytes.NewBuffer(data)

	dec := gob.NewDecoder(buf)
	rulesets := make([]*Ruleset, 0)
	err := dec.Decode(&rulesets)
	if err != nil {
		d.log.Errorf("Could not decode: %v", err)
		return nil, nil, err
	}

	// The compiled regular expressions aren't serialized, so we have to manually
	// compile them.
	plains := make(map[string]*ruleset)
	wildcards := radix.New()
	for _, rs := range rulesets {
		wildcards = d.addRuleset(rs, plains, wildcards)
	}

	d.log.Debugf("Loaded HTTPS Everywhere in %v", time.Now().Sub(start).String())
	return plains, wildcards, nil
}

func (d *deserializer) addRuleset(rs *Ruleset, plains map[string]*ruleset, wildcards *radix.Tree) *radix.Tree {
	// If the rule is turned off, ignore it. This should be handled in
	// preprocessing, but better to be sure.
	if len(rs.Off) > 0 {
		return wildcards
	}
	// ignore any rule that is mixedcontent-only.
	if rs.Platform == "mixedcontent" {
		return wildcards
	}

	// Make a simpler in memory version.
	rsCopy := &ruleset{
		exclusion: make([]exclusion, 0),
		rule:      make([]rule, 0),
	}
	for _, e := range rs.Exclusion {
		pat, err := regexp.Compile(e.Pattern)
		if err != nil {
			d.log.Debugf("Compile failed?? %v", err)
			return wildcards
		}
		rsCopy.exclusion = append(rsCopy.exclusion, exclusion{
			pattern: pat,
		})
	}

	for _, r := range rs.Rule {
		from, err := regexp.Compile(r.From)
		if err != nil {
			d.log.Debugf("Compile failed?? %v", err)
			return wildcards
		}
		rsCopy.rule = append(rsCopy.rule, rule{
			from: from,
			to:   d.normalizeTo(r.To),
		})
	}

	for _, target := range rs.Target {
		//h.log.Debugf("Adding target host %v", target.Host)
		if isSuffixTarget(&target) {
			//h.log.Debug("Adding suffix target")
			wildcards.Insert(strings.TrimSuffix(target.Host, "*"), rsCopy)
		} else if isPrefixTarget(&target) {
			input := reverse(strings.TrimPrefix(target.Host, "*"))
			wildcards.Insert(input, rsCopy)
		} else {
			plains[target.Host] = rsCopy
		}
	}
	return wildcards
}

func isPrefixTarget(target *Target) bool {
	return strings.HasPrefix(target.Host, "*")
}

func isSuffixTarget(target *Target) bool {
	return strings.HasSuffix(target.Host, "*")
}

func (d *deserializer) normalizeTo(to string) string {
	// Go handles references to matching groups in the replacement text
	// differently from PCRE. PCRE considers $1xxx to be the first match
	// followed by xxx, whereas in Go that's considered to be the named group
	// "$1xxx".
	// See: https://golang.org/pkg/regexp/#Regexp.Expand
	normalizedTo := strings.Replace(to, "$1", "${1}", -1)
	for i := 1; i < 10; i++ {
		old := "$" + strconv.Itoa(i)
		new := "${" + strconv.Itoa(i) + "}"
		normalizedTo = strings.Replace(normalizedTo, old, new, -1)
	}
	return normalizedTo
}
