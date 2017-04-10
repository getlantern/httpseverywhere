package httpseverywhere

import (
	"bytes"
	"encoding/gob"
	"encoding/xml"
	"io/ioutil"
	"net/url"
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
	//targets := make(map[string]*Targets)
	domainsToRulesets := make(map[string][]*Rules)
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		p.log.Fatal(err)
	}

	var errors int
	for _, file := range files {
		b, errr := ioutil.ReadFile(filepath.Join(dir, file.Name()))
		if errr != nil {
			p.log.Errorf("Error reading file: %v", err)
		} else {
			p.log.Debugf("Adding rule for file: %v", file.Name())
			processed := p.AddRuleSet(b, domainsToRulesets)
			if !processed {
				errors++
			}
		}
	}

	p.log.Debugf("Loaded rules with %v targets and %v errors", len(domainsToRulesets), errors)

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	p.log.Debugf("Encoding...")
	err = enc.Encode(domainsToRulesets)
	p.log.Debug("Finished decoding...")
	if err != nil {
		p.log.Fatalf("encode error: %v", err)
	}
	p.log.Debugf("Writing gob file")
	ioutil.WriteFile("rulesets.gob", buf.Bytes(), 0644)
}

// AddRuleSet adds the specified rule set to the map of targets. Returns
// whether or not the rule processed correctly and whether or not the
// target was a duplicate. Duplicates are ignored but are considered to have
// processed correctly.
func (p *preprocessor) AddRuleSet(rules []byte, domainsToRulesets map[string][]*Rules) bool {
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

	err := p.ruleSetToRules(&ruleset, domainsToRulesets)
	if err != nil {
		return false
	}
	return true
}

func (p *preprocessor) extractRoot(host string) (string, error) {
	// This artificially turns the target into a valid URL for processing.
	normalizedURL := "http://" + host
	url, err := url.Parse(normalizedURL)
	if err != nil {
		p.log.Errorf("Could not parse URL: %v with error %v", url, err)
		return "", err
	}
	_, root := extractHostAndRoot(url)
	return root, nil
}

func (p *preprocessor) rootForWildcardSuffix(host string) string {
	var urlStr string
	// We have to handle this carefully because if we just replace the com.* with
	// com.uk, for example, we won't properly extract the root domain (it will
	// be "com")
	if strings.HasSuffix(host, ".com.*") {
		urlStr = strings.Replace(host, ".com.*", ".com", 1)
	} else {
		// We just use uk here to make it a valid suffix
		urlStr = strings.Replace(host, "*", "uk", 1)
	}

	//p.log.Debugf("Extracting wildcard suffix for URL %v", urlStr)
	root, err := p.extractRoot(urlStr)
	if err != nil {
		return urlStr
	}
	return root
}

func (p *preprocessor) ruleSetToRules(set *Ruleset, domainsToRulesets map[string][]*Rules) error {
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
			return err
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
			return err
		}
		exclude = append(exclude, &exclusion{Pattern: e.Pattern, pattern: pattern})
	}

	rules := &Rules{
		Rules:      mod,
		Exclusions: exclude,
	}
	p.makeTargets(set, domainsToRulesets, rules)
	return nil
}

func (p *preprocessor) makeTargets(set *Ruleset, domainsToRulesets map[string][]*Rules, rules *Rules) error {

	regexTargets := make([]*RegexTarget, 0)
	plainTargets := make(map[string]bool)
	rules.RegexTargets = regexTargets
	rules.PlainTargets = plainTargets
	for _, target := range set.Target {
		if strings.HasPrefix(target.Host, "*") {
			root, err := p.extractRoot(strings.Replace(target.Host, "*", "pre", 1))
			if err != nil {
				p.log.Errorf("Could not extract root? %v", err)
				return err
			}

			// We need to make it into a valid regexp.
			re := "." + target.Host

			t, err := p.newRegexTarget(re)
			if err != nil {
				return err
			}
			regexTargets = append(regexTargets, t)
			if existing, ok := domainsToRulesets[root]; ok {
				domainsToRulesets[root] = append(existing, rules)
			} else {
				r := make([]*Rules, 0)
				r = append(r, rules)
				domainsToRulesets[root] = r
			}
		} else if strings.HasSuffix(target.Host, "*") {
			root := p.rootForWildcardSuffix(target.Host)
			p.log.Debugf("Extracting wildcard suffix for host %v", target.Host)
			t, err := p.newRegexTarget(target.Host)
			if err != nil {
				return err
			}
			regexTargets = append(regexTargets, t)
			if existing, ok := domainsToRulesets[root]; ok {
				domainsToRulesets[root] = append(existing, rules)
			} else {
				r := make([]*Rules, 0)
				r = append(r, rules)
				domainsToRulesets[root] = r
			}
		} else {
			root, err := p.extractRoot(target.Host)
			if err != nil {
				return err
			}
			if len(root) == 0 {
				p.log.Debugf("Found empty string for: %v", target.Host)
			}
			rules.PlainTargets[target.Host] = true
			if existing, ok := domainsToRulesets[root]; ok {
				domainsToRulesets[root] = append(existing, rules)
			} else {
				r := make([]*Rules, 0)
				r = append(r, rules)
				domainsToRulesets[root] = r
			}
		}
	}
	return nil
}

func (p *preprocessor) newRegexTarget(host string) (*RegexTarget, error) {
	re, err := regexp.Compile(host)
	if err != nil {
		p.log.Errorf("Could not compile %v, got %v", host, err)
		return nil, err
	}
	return &RegexTarget{Regex: host, regex: re}, nil
}
