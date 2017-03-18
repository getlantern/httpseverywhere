package httpseverywhere

import (
	"bytes"
	"encoding/gob"
	"encoding/xml"
	"net/url"
	"regexp"
	"strings"

	"github.com/getlantern/golog"
	"github.com/getlantern/tldextract"
)

var log = golog.LoggerFor("httpseverywhere")

// rewrite changes an HTTP URL to rewrite.
type rewrite func(url string) (string, bool)

// Rewrite exports the rewrite method for users of this library.
var Rewrite = new()

type https struct {
	log     golog.Logger
	targets map[string]*Rules
}

// A rule maps the regular expression to match and the string to change it to.
// It also stores the compiled regular expression for efficiency.
type rule struct {
	from *regexp.Regexp
	From string
	To   string
}

// An exclusion just contains the compiled regular expression exclusion pattern.
type exclusion struct {
	Pattern string
	pattern *regexp.Regexp
}

// Rules is a struct containing rules and exclusions for a given rule set. This
// is public so that we can encode and decode it from GOB format.
type Rules struct {
	Rules      []*rule
	Exclusions []*exclusion
}

// new creates a new rewrite instance from embedded GOB data.
func new() rewrite {
	data := MustAsset("targets.gob")
	buf := bytes.NewBuffer(data)

	dec := gob.NewDecoder(buf)
	targets := make(map[string]*Rules)
	err := dec.Decode(&targets)
	if err != nil {
		log.Errorf("Could not decode: %v", err)
		return nil
	}

	// The compiled regular expressions aren't serialized, so we have to manually
	// compile them.
	for _, v := range targets {
		for _, r := range v.Rules {
			r.from, _ = regexp.Compile(r.From)
		}

		for _, e := range v.Exclusions {
			e.pattern, _ = regexp.Compile(e.Pattern)
		}
	}
	return newRewrite(targets)
}

// AddRuleSet adds the specified rule set to the map of targets. Returns
// whether or not the rule processed correctly and whether or not the
// target was a duplicate. Duplicates are ignored but are considered to have
// processed correctly.
func AddRuleSet(rules []byte, targets map[string]*Rules) (bool, int) {
	var r Ruleset
	xml.Unmarshal(rules, &r)

	// If the rule is turned off, ignore it.
	if len(r.Off) > 0 {
		return false, 0
	}

	// We don't run on any platforms (aka Tor) that support mixed content, so
	// ignore any rule that is mixedcontent-only.
	if r.Platform == "mixedcontent" {
		return false, 0
	}

	rs, err := ruleSetToRules(r)
	if err != nil {
		return false, 0
	}

	duplicates := 0
	extract := tldextract.New()
	for _, target := range r.Target {
		if strings.HasPrefix(target.Host, "*") {
			// This artificially turns the target into a valid URL for processing
			// by TLD extract.
			urlStr := "http://" + strings.Replace(target.Host, "*", "SUBDOMAIN", 1)
			e := extract.Extract(urlStr)

			if strings.Contains(e.Sub, ".") {
				log.Debugf("Ingoring wildcard rule with multiple subdomains: %+v;%s\n", e, target.Host)
				return false, duplicates
			}
			duplicates += addRules(targets, target.Host, rs)
		} else {
			duplicates += addRules(targets, target.Host, rs)
		}
	}
	return true, duplicates
}

func addRules(targets map[string]*Rules, host string, rules *Rules) int {
	if _, ok := targets[host]; ok {
		// Ignoring duplicate.
		return 1
	}
	targets[host] = rules
	return 0
}

// rewrite converts the given URL to HTTPS if there is an associated rule for
// it.
func (r *Rules) rewrite(url string) (string, bool) {
	for _, exclude := range r.Exclusions {
		if exclude.pattern.MatchString(url) {
			return url, false
		}
	}
	for _, rule := range r.Rules {
		if rule.from.MatchString(url) {
			return rule.from.ReplaceAllString(url, rule.To), true
		}
	}
	return url, false
}

// newHTTPS creates a new rewrite instance from a single rule set string. In
// practice this is used for testing.
func newHTTPS(rules string) (rewrite, map[string]*Rules) {
	targets := make(map[string]*Rules)
	AddRuleSet([]byte(rules), targets)
	return newRewrite(targets), targets
}

func newRewrite(targets map[string]*Rules) rewrite {
	return (&https{log: log, targets: targets}).rewrite
}

func ruleSetToRules(set Ruleset) (*Rules, error) {
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
			log.Debugf("Could not compile regex: %v", err)
			return nil, err
		}
		mod = append(mod, &rule{From: r.From, from: f, To: r.To})

	}
	exclude := make([]*exclusion, 0)
	for _, e := range set.Exclusion {
		p, err := regexp.Compile(e.Pattern)
		if err != nil {
			log.Debugf("Could not compile regex for exclusion: %v", err)
			return nil, err
		}
		exclude = append(exclude, &exclusion{Pattern: e.Pattern, pattern: p})
	}
	return &Rules{Rules: mod, Exclusions: exclude}, nil
}

func (h *https) rewrite(urlStr string) (string, bool) {
	u, err := url.Parse(urlStr)
	if err != nil {
		log.Errorf("Could not parse domain %v", err)
		return urlStr, false
	}
	domain := stripPort(u.Host)
	if err != nil {
		return urlStr, false
	}

	// We need to check for both the domain itself as well as the wildcard domain.

	if rules, ok := h.targets[domain]; ok {
		//h.log.Debugf("Got rules: %+v", rules)
		return rules.rewrite(urlStr)
	}
	if rules, ok := h.targets[stripTLD(domain)+"*"]; ok {
		//h.log.Debugf("Got suffix rules: %+v", rules)
		return rules.rewrite(urlStr)
	}
	if rules, ok := h.targets["*."+stripSubdomains(domain)]; ok {
		//h.log.Debugf("Got prefix rules: %+v", rules)
		return rules.rewrite(urlStr)
	}
	return urlStr, false
}

func stripSubdomains(hostport string) string {
	dot := strings.IndexByte(hostport, '.')
	if dot == -1 {
		return hostport
	} else if len(hostport)-dot < 5 {
		return hostport
	}
	dot++
	return stripSubdomains(hostport[dot:])
}

func stripPort(hostport string) string {
	colon := strings.IndexByte(hostport, ':')
	if colon == -1 {
		return hostport
	}
	if i := strings.IndexByte(hostport, ']'); i != -1 {
		return strings.TrimPrefix(hostport[:i], "[")
	}
	return hostport[:colon]
}

func stripTLD(domain string) string {
	// Note the domain here is already stripped of all subdomains.
	dot := strings.IndexByte(domain, '.')
	if dot == -1 {
		return domain
	}
	dot++
	return domain[:dot]
}
