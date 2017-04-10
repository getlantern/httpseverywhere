package httpseverywhere

import (
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/getlantern/golog"
)

var (
	log = golog.LoggerFor("httpseverywhere")
)

// Rewrite exports the rewrite method for users of this library.
//var Rewrite = newAsync()

// rewrite changes an HTTP URL to rewrite.
type rewrite func(url *url.URL) (string, bool)

type https struct {
	// This is a map of root host names to Targets -- map[string]*Targets
	domainsToRulesets atomic.Value
	runs              int64
	totalTime         int64
	max               int64
	maxHost           string
	statM             sync.RWMutex
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
	//Targets    []string
	RegexTargets []*RegexTarget
	PlainTargets map[string]bool
	Rules        []*rule
	Exclusions   []*exclusion
}

type RegexTarget struct {
	Regex string
	regex *regexp.Regexp
}

//var DomainsToRulesets map[string]*Rules

// Targets contains the target hosts for the given base domain.
//type Targets struct {

//wildcardPrefix []*regexp.Regexp
//wildcardSuffix []*regexp.Regexp

//wildcardPrefix []*Rules
//wildcardSuffix []*Rules

// We use maps here to filter duplicates. Note these are only used in
// preprocessing and in deserialization.
//WildcardPrefix map[string]*Rules
//WildcardSuffix map[string]*Rules

//Rules *Rules
//}

// new creates a new rewrite instance from embedded GOB data with asynchronous
// loading of the rule sets to allow the caller to about around a 2 second
// delay.
func newAsync() rewrite {
	h := &https{}

	h.domainsToRulesets.Store(make(map[string][]*Rules))
	go func() {
		d := newDeserializer()
		temp := d.newDomainsToRulesets()
		h.domainsToRulesets.Store(temp)
	}()

	return h.rewrite
}

// newSync creates a new rewrite instance from embedded GOB data.
func newSync() rewrite {
	h := &https{}
	d := newDeserializer()
	h.domainsToRulesets.Store(d.newDomainsToRulesets())
	return h.rewrite
}

func (h *https) rewrite(url *url.URL) (string, bool) {
	if url.Scheme != "http" {
		log.Debug("NOT HTTP?")
		return "", false
	}
	start := time.Now()
	host, root := extractHostAndRoot(url)

	if len(root) == 0 {
		log.Error("Root is the empty string!")
		return "", false
	}
	if rulesets, ok := h.domainsToRulesets.Load().(map[string][]*Rules)[root]; ok {
		for _, ruleset := range rulesets {
			https, done := ruleset.rewrite(url.String(), host)
			if done {
				h.addTiming(time.Now().Sub(start), url.String())
				return https, done
			}
		}
		//https, done := rules.rewrite(url.String(), host)
		//h.addTiming(time.Now().Sub(start), url.String())

		//return https, done
	}
	log.Debugf("Not target for root %v", root)

	return "", false
}

func (h *https) addTiming(dur time.Duration, host string) {
	nan := dur.Nanoseconds() / int64(time.Millisecond)
	h.statM.Lock()
	h.runs++
	h.totalTime += nan
	if nan > h.max {
		h.max = nan
		h.maxHost = host
	}
	h.statM.Unlock()

	h.statM.RLock()

	log.Debugf("Average running time: %vms", float64(h.totalTime/h.runs))
	log.Debugf("Max running time: %vms for host: %v", h.max, h.maxHost)
	h.statM.RUnlock()
}

func extractHostAndRoot(url *url.URL) (string, string) {
	host := withoutPort(url.Host)

	// We ignore the second return value which is just a bool indicating whether
	// it's an official ICANN TLD.
	tld, _ := publicsuffix.PublicSuffix(host)

	// Because some TLDs such as "co.uk" include "."s, we strip the TLD prior
	// to stripping subdomains.
	noTLD := strings.TrimSuffix(host, "."+tld)
	root := stripSubdomains(noTLD)
	return host, root
}

func withoutPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}

func stripSubdomains(host string) string {
	host = strings.TrimSpace(host)
	parts := strings.Split(host, ".")
	return parts[len(parts)-1]
}

/*
func (t *Targets) rewrite(originalURL *url.URL, host string) (string, bool) {
	// We basically want to apply the associated set of rules if any of the
	// targets match the url.
	url := originalURL.String()
	log.Debugf("Attempting to rewrite url %v with %+v", url)
	for k := range t.Plain {
		if host == k {
			log.Debugf("Hosts equal: %v and %v", k, host)
			if r, done := t.Rules.rewrite(url); done {
				return r, done
			}
		}
	}
	if r, done := t.matchTargets(url, t.wildcardPrefix); done {
		return r, done
	}
	return t.matchTargets(url, t.wildcardSuffix)
}

func (t *Targets) matchTargets(url string, rules []*Rules) (string, bool) {
	for _, pre := range targets {
		if pre.MatchString(url) {
			log.Debugf("Got string match: %v matched %v", url, pre.String())
			if r, done := t.Rules.rewrite(url); done {
				return r, done
			}
		}
	}
	return "", false
}
*/

// rewrite converts the given URL to HTTPS if there is an associated rule for
// it.
func (r *Rules) rewrite(url string, host string) (string, bool) {
	if !r.matchesTargets(url, host) {
		return "", false
	}
	for _, exclude := range r.Exclusions {
		if exclude.pattern.MatchString(url) {
			return "", false
		}
	}
	for _, rule := range r.Rules {
		log.Debugf("Rule %v", rule.From)
	}
	for _, rule := range r.Rules {
		log.Debugf("Checking %v", rule.From)
		if rule.from.MatchString(url) {
			log.Debugf("Matched on %v", rule.From)
			return rule.from.ReplaceAllString(url, rule.To), true
		} else {
			log.Debugf("Did not match URL: %v", url)
		}
	}
	return "", false
}

func (r *Rules) matchesTargets(url, host string) bool {
	//var matched bool
	if _, ok := r.PlainTargets[url]; ok {
		return true
	}
	log.Debugf("No match for URL %v in plain targets: %+v", url, r.PlainTargets)
	// TODO: MAKE SURE TO TEST THIS!!
	for _, target := range r.RegexTargets {
		if target.regex.MatchString(url) {
			return true
		}
	}
	return false
}
