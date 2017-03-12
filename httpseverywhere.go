package httpseverywhere

import (
	"encoding/xml"
	"net/url"
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
	rx *regexp.Regexp
	to string
}

type rules struct {
	rules []*rule
}

func (r *rules) ToHTTPS(url string) (string, bool) {
	for _, rule := range r.rules {
		match := rule.rx.MatchString(url)
		if match {
			return rule.rx.ReplaceAllString(url, rule.to), true
		}
		log.Debugf("Rule %v did not match string: %v", rule.rx.String(), url)
	}
	return url, false
}

func NewHTTPS(rules string) ToHTTPS {

	targets := make(map[string]ToHTTPS)
	addRuleSet(rules, targets)
	return &https{log: log, targets: targets}
}

func addRuleSet(rules string, targets map[string]ToHTTPS) {
	b := []byte(rules)
	var r Ruleset
	xml.Unmarshal(b, &r)

	rs := ruleSetToRules(r)

	for _, target := range r.Target {
		log.Debugf("Adding host: %v", target.Host)
		// TODO: If this is a wildcard domain, add a flag to the base domain to
		// signify to check for either a LEADING or a TRAILING wildcard.
		targets[target.Host] = rs
	}

	log.Debugf("targets: %+v", targets)
}

func ruleSetToRules(set Ruleset) ToHTTPS {
	mod := make([]*rule, len(set.Rule))
	for i, r := range set.Rule {
		// Precompile the regex to make things faster when actually processing
		// rules for live traffic.
		f := regexp.MustCompile(r.From)
		mod[i] = &rule{rx: f, to: r.To}
	}
	return &rules{rules: mod}
}

func (h *https) ToHTTPS(urlStr string) (string, bool) {
	//domain, err := h.parseDomain(urlStr)
	u, err := url.Parse(urlStr)
	if err != nil {
		log.Errorf("Could not parse domain %v", err)
		return urlStr, false
	}
	domain := stripPort(u.Host)
	h.log.Debugf("Got domain: %s", domain)
	if err != nil {
		return urlStr, false
	}

	// We need to check for both the domain itself as well as the wildcard domain.

	if rules, ok := h.targets[domain]; ok {
		h.log.Debugf("Got rules: %+v", rules)
		return rules.ToHTTPS(urlStr)
	}
	if rules, ok := h.targets[stripTLD(domain)+"*"]; ok {
		h.log.Debugf("Got suffix rules: %+v", rules)
		return rules.ToHTTPS(urlStr)
	}
	if rules, ok := h.targets["*."+stripSubdomains(domain)]; ok {
		h.log.Debugf("Got rules: %+v", rules)
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
