package httpseverywhere

import (
	"bytes"
	"encoding/gob"
	"encoding/xml"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/getlantern/golog"
)

// Preprocessor is a struct for preprocessing rules into a GOB file.
var Preprocessor = &preprocessor{
	log: golog.LoggerFor("httpseverywhere-preprocessor"),
}

type preprocessor struct {
	log golog.Logger
}

// Preprocess adds all of the rules in the specified directory.
func (p *preprocessor) Preprocess(dir string) {
	targets := make(map[string]*Targets)
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		p.log.Fatal(err)
	}

	var errors int
	for _, file := range files {
		/*
			if !strings.HasPrefix(file.Name(), "Name.com") {
				continue
			}
		*/
		b, errr := ioutil.ReadFile(filepath.Join(dir, file.Name()))
		if errr != nil {
			//log.Errorf("Error reading file: %v", err)
		} else {
			processed := p.AddRuleSet(b, targets)
			if !processed {
				errors++
			}
		}
	}

	p.log.Debugf("Loaded rules with %v targets and %v errors", len(targets), errors)

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	// Encode (send) the value.
	err = enc.Encode(targets)
	if err != nil {
		p.log.Fatalf("encode error: %v", err)
	}
	ioutil.WriteFile("targets.gob", buf.Bytes(), 0644)
}

// AddRuleSet adds the specified rule set to the map of targets. Returns
// whether or not the rule processed correctly and whether or not the
// target was a duplicate. Duplicates are ignored but are considered to have
// processed correctly.
func (p *preprocessor) AddRuleSet(rules []byte, rootsToTargets map[string]*Targets) bool {
	var ruleset Ruleset
	xml.Unmarshal(rules, &ruleset)

	// If the rule is turned off, ignore it.
	if len(ruleset.Off) > 0 {
		return false
	}

	// We don't run on any platforms (aka Tor) that support mixed content, so
	// ignore any rule that is mixedcontent-only.
	if ruleset.Platform == "mixedcontent" {
		return false
	}

	rs, err := p.ruleSetToRules(ruleset)
	if err != nil {
		return false
	}

	// Now add the rules to all targets for the rule set.
	for _, target := range ruleset.Target {
		// The host roots key the targets map so we can quickly determine if
		// there are any rules at all for a given root in O(1) time.
		if strings.HasPrefix(target.Host, "*") {
			// This artificially turns the target into a valid URL for processing
			// by TLD extract.
			urlStr := "http://" + strings.Replace(target.Host, "*", "pre", 1)
			result := extract.Extract(urlStr)

			// We need to make it into a valid regexp.
			re := "." + target.Host
			if existing, ok := rootsToTargets[result.Root]; ok {
				p.addWildcardPrefix(existing, re)
			} else {
				p.log.Debugf("Adding wildcard prefix for %v", target.Host)
				targs := p.newTargets(rs)
				rootsToTargets[result.Root] = targs
				p.addWildcardPrefix(targs, re)
			}
		} else if strings.HasSuffix(target.Host, "*") {
			root := p.rootForWildcardSuffix(target.Host)
			p.log.Debugf("Extracting wildcard suffix for host %v", target.Host)
			if existing, ok := rootsToTargets[root]; ok {
				p.log.Debugf("Adding to existing wildcard suffix targets for %v", root)
				p.addWildcardSuffix(existing, target.Host)
			} else {
				targs := p.newTargets(rs)
				rootsToTargets[root] = targs
				p.addWildcardSuffix(targs, target.Host)
				p.log.Debugf("Adding new wildcard suffix targets for %v", root)
			}
		} else {
			result := extract.Extract(target.Host)
			if existing, ok := rootsToTargets[result.Root]; ok {
				existing.Plain[target.Host] = true
			} else {
				p.addPlain(rootsToTargets, result.Root, target.Host, p.newTargets(rs))
			}
		}
	}
	return true
}

func (p *preprocessor) rootForWildcardSuffix(host string) string {
	var urlStr string
	// We have to handle this carefully because if we just replace the com.* with
	// com.uk, for example, we won't properly extract the root domain (it will
	// be "com")
	if strings.HasSuffix(host, ".com.*") {
		urlStr = "http://" + strings.Replace(host, ".com.*", ".com", 1)
	} else {
		urlStr = "http://" + strings.Replace(host, "*", "uk", 1)
	}

	p.log.Debugf("Extracting wildcard suffix for URL %v", urlStr)
	result := extract.Extract(urlStr)
	return result.Root
}

func (p *preprocessor) addPlain(rootsToTargets map[string]*Targets,
	rootDomain, fullDomain string, targets *Targets) {
	if t, ok := rootsToTargets[rootDomain]; ok {
		t.Plain[fullDomain] = true
		return
	}
	targets.Plain[fullDomain] = true
	rootsToTargets[rootDomain] = targets
}

func (p *preprocessor) addWildcardPrefix(targets *Targets, host string) {
	re, err := regexp.Compile(host)
	if err != nil {
		p.log.Errorf("Could not compile regex for target host %v: %v", host, err)
		return
	}
	if val, ok := targets.WildcardPrefix[host]; ok {
		p.log.Debugf("Ignoring duplicate prefix for %v", val)
		return
	}
	targets.WildcardPrefix[host] = true
	targets.wildcardPrefix = append(targets.wildcardPrefix, re)

}

func (p *preprocessor) addWildcardSuffix(targets *Targets, host string) {
	p.log.Debugf("Compiling wildcard suffix: %v", host)
	re, err := regexp.Compile(host)
	if err != nil {
		p.log.Errorf("Could not compile regex for target host %v: %v", host, err)
		return
	}
	if _, ok := targets.WildcardSuffix[host]; ok {
		p.log.Debugf("Ignoring duplicate suffix for %v", host)
		return
	}

	p.log.Debugf("Adding wildcard suffix for %v", host)
	targets.WildcardSuffix[host] = true
	targets.wildcardSuffix = append(targets.wildcardSuffix, re)
}

func (p *preprocessor) ruleSetToRules(set Ruleset) (*Rules, error) {
	mod := make([]*rule, 0)
	for _, r := range set.Rule {
		// We ignore any rules that attempt to redirect to HTTP, as they would
		// trigger mixed content in most cases (all cases in browsers that don't
		// allow mixed content)?
		if r.To == "http:" {
			continue
		}
		f, err := regexp.Compile(r.From)
		if err != nil {
			p.log.Debugf("Could not compile regex: %v", err)
			return nil, err
		}

		// Go handles references to matching groups in the replacement text
		// differently from PCRE. PCRE considers $1xxx to be the first match
		// followed by xxx, whereas in Go that's considered to be the named group
		// "$1xxx".
		// See: https://golang.org/pkg/regexp/#Regexp.Expand
		normalizedTo := strings.Replace(r.To, "$1", "${1}", -1)
		for i := 1; i < 10; i++ {
			old := "$" + strconv.Itoa(i)
			new := "${" + strconv.Itoa(i) + "}"
			normalizedTo = strings.Replace(normalizedTo, old, new, -1)
		}
		mod = append(mod, &rule{From: r.From, from: f, To: normalizedTo})

	}
	exclude := make([]*exclusion, 0)
	for _, e := range set.Exclusion {
		pattern, err := regexp.Compile(e.Pattern)
		if err != nil {
			p.log.Debugf("Could not compile regex for exclusion: %v", err)
			return nil, err
		}
		exclude = append(exclude, &exclusion{Pattern: e.Pattern, pattern: pattern})
	}
	return &Rules{Rules: mod, Exclusions: exclude}, nil
}

func (p *preprocessor) newTargets(rules *Rules) *Targets {
	return &Targets{
		Rules:          rules,
		Plain:          make(map[string]bool),
		WildcardPrefix: make(map[string]bool),
		WildcardSuffix: make(map[string]bool),
		wildcardPrefix: make([]*regexp.Regexp, 0),
		wildcardSuffix: make([]*regexp.Regexp, 0),
	}
}
