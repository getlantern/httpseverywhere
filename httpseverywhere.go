package httpseverywhere

import (
	"encoding/xml"
	"io/ioutil"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/getlantern/golog"
)

var log = golog.LoggerFor("httpseverywhere")

// ToHTTPS changes an HTTP URL to HTTPS.
type ToHTTPS interface {
	ToHTTPS(url string) (string, bool)
}

type https struct {
	log     golog.Logger
	targets map[string]ToHTTPS
}

type rule struct {
	from *regexp.Regexp
	to   string
}

type exclusion struct {
	pattern *regexp.Regexp
}

type rules struct {
	rules      []*rule
	exclusions []*exclusion
}

func (r *rules) ToHTTPS(url string) (string, bool) {
	for _, exclude := range r.exclusions {
		if exclude.pattern.MatchString(url) {
			return url, false
		}
	}
	for _, rule := range r.rules {
		if rule.from.MatchString(url) {
			return rule.from.ReplaceAllString(url, rule.to), true
		}
	}
	return url, false
}

// AddAllRules adds all of the rules in the specified directory.
func AddAllRules(dir string) ToHTTPS {
	targets := make(map[string]ToHTTPS)
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}

	var errors int
	for _, file := range files {
		b, err := ioutil.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			log.Errorf("Error reading file: %v", err)
		} else {
			if !addRuleSet(b, targets) {
				errors++
			}
		}
	}

	log.Debugf("Loaded rules with %v targets and %v errors", len(targets), errors)
	return &https{log: log, targets: targets}
}

// NewHTTPS creates a new ToHTTPS instance from a single rule set string.
func NewHTTPS(rules string) ToHTTPS {
	targets := make(map[string]ToHTTPS)
	addRuleSet([]byte(rules), targets)
	return &https{log: log, targets: targets}
}

func addRuleSet(rules []byte, targets map[string]ToHTTPS) bool {
	var r Ruleset
	xml.Unmarshal(rules, &r)

	// If the rule is turned off, ignore it.
	if len(r.Off) > 0 {
		return false
	}

	// We don't run on any platforms (aka Tor) that support mixed content, so
	// ignore any rule that is mixedcontent-only.
	if r.Platform == "mixedcontent" {
		return false
	}

	rs, err := ruleSetToRules(r)
	if err != nil {
		return false
	}

	for _, target := range r.Target {
		targets[target.Host] = rs
	}
	return true
}

func ruleSetToRules(set Ruleset) (ToHTTPS, error) {
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
		mod = append(mod, &rule{from: f, to: r.To})

	}
	exclude := make([]*exclusion, 0)
	for _, e := range set.Exclusion {
		p, err := regexp.Compile(e.Pattern)
		if err != nil {
			log.Debugf("Could not compile regex for exclusion: %v", err)
			return nil, err
		}
		exclude = append(exclude, &exclusion{pattern: p})
	}
	return &rules{rules: mod, exclusions: exclude}, nil
}

func (h *https) ToHTTPS(urlStr string) (string, bool) {
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
		return rules.ToHTTPS(urlStr)
	}
	if rules, ok := h.targets[stripTLD(domain)+"*"]; ok {
		//h.log.Debugf("Got suffix rules: %+v", rules)
		return rules.ToHTTPS(urlStr)
	}
	if rules, ok := h.targets["*."+stripSubdomains(domain)]; ok {
		//h.log.Debugf("Got prefix rules: %+v", rules)
		return rules.ToHTTPS(urlStr)
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
