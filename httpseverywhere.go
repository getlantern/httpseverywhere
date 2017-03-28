package httpseverywhere

import (
	"regexp"
	"sync"
	"sync/atomic"

	"github.com/getlantern/golog"
	"github.com/getlantern/tldextract"
)

var (
	log     = golog.LoggerFor("httpseverywhere")
	extract = tldextract.New()
)

// Rewrite exports the rewrite method for users of this library.
var Rewrite = newAsync()

// rewrite changes an HTTP URL to rewrite.
type rewrite func(url string) (string, bool)

type https struct {
	log golog.Logger
	//hostsToTargets map[string]*Targets
	sync.RWMutex
	hostsToTargets atomic.Value
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

// Targets contains the target hosts for the given base domain.
type Targets struct {
	wildcardPrefix []*regexp.Regexp
	wildcardSuffix []*regexp.Regexp

	// We use maps here to filter duplicates.
	WildcardPrefix map[string]bool
	WildcardSuffix map[string]bool
	Plain          map[string]bool

	Rules *Rules
}

// new creates a new rewrite instance from embedded GOB data with asynchronous
// loading of the rule sets to allow the caller to about around a 2 second
// delay.
func newAsync() rewrite {
	h := &https{
		log: golog.LoggerFor("httpseverywhere-https"),
	}

	h.hostsToTargets.Store(make(map[string]*Targets))
	go func() {
		d := newDeserializer()
		temp := d.newHostsToTargets()
		h.hostsToTargets.Store(temp)
	}()

	return h.rewrite
}

// newSync creates a new rewrite instance from embedded GOB data.
func newSync() rewrite {
	h := &https{
		log: golog.LoggerFor("httpseverywhere-https"),
	}

	d := newDeserializer()
	h.hostsToTargets.Store(d.newHostsToTargets())
	return h.rewrite
}

func (h *https) rewrite(urlStr string) (string, bool) {
	result := extract.Extract(urlStr)
	domain := result.Root + "." + result.Tld
	if targets, ok := h.hostsToTargets.Load().(map[string]*Targets)[result.Root]; ok {
		return targets.rewrite(urlStr, domain)
	}
	return urlStr, false
}

func (t *Targets) rewrite(url, domain string) (string, bool) {
	// We basically want to apply the associated set of rules if any of the
	// targets match the url.
	log.Debugf("Attempting to rewrite %v", domain)
	for k := range t.Plain {
		if domain == k {
			return t.Rules.rewrite(url)
		}
	}
	if r, done := t.matchTargets(url, t.wildcardPrefix); done {
		return r, done
	}
	return t.matchTargets(url, t.wildcardSuffix)
}

func (t *Targets) matchTargets(url string, targets []*regexp.Regexp) (string, bool) {
	for _, pre := range targets {
		if pre.MatchString(url) {
			r, done := t.Rules.rewrite(url)
			if done {
				return r, done
			}
		}
	}
	return url, false
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
