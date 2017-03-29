package httpseverywhere

import (
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"

	"golang.org/x/net/publicsuffix"

	"github.com/getlantern/golog"
)

var (
	log = golog.LoggerFor("httpseverywhere")
)

// Rewrite exports the rewrite method for users of this library.
var Rewrite = newAsync()

// rewrite changes an HTTP URL to rewrite.
type rewrite func(url *url.URL) (string, bool)

type https struct {
	// This is a map of root host names to Targets -- map[string]*Targets
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
	Plain map[string]bool

	wildcardPrefix []*regexp.Regexp
	wildcardSuffix []*regexp.Regexp

	// We use maps here to filter duplicates. Note these are only used in
	// preprocessing and in deserialization.
	WildcardPrefix map[string]bool
	WildcardSuffix map[string]bool

	Rules *Rules
}

// new creates a new rewrite instance from embedded GOB data with asynchronous
// loading of the rule sets to allow the caller to about around a 2 second
// delay.
func newAsync() rewrite {
	h := &https{}

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
	h := &https{}
	d := newDeserializer()
	h.hostsToTargets.Store(d.newHostsToTargets())
	return h.rewrite
}

func (h *https) rewrite(url *url.URL) (string, bool) {
	if url.Scheme != "http" {
		return "", false
	}
	host, root := extractHostAndRoot(url)

	if len(root) == 0 {
		log.Error("Root is the empty string!")
		return "", false
	}
	if targets, ok := h.hostsToTargets.Load().(map[string]*Targets)[root]; ok {
		return targets.rewrite(url, host)
	}
	return "", false
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

func (t *Targets) rewrite(originalURL *url.URL, host string) (string, bool) {
	// We basically want to apply the associated set of rules if any of the
	// targets match the url.
	url := originalURL.String()
	log.Debugf("Attempting to rewrite url %v", url)
	for k := range t.Plain {
		if host == k {
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

func (t *Targets) matchTargets(url string, targets []*regexp.Regexp) (string, bool) {
	for _, pre := range targets {
		if pre.MatchString(url) {
			if r, done := t.Rules.rewrite(url); done {
				return r, done
			}
		}
	}
	return "", false
}

// rewrite converts the given URL to HTTPS if there is an associated rule for
// it.
func (r *Rules) rewrite(url string) (string, bool) {
	for _, exclude := range r.Exclusions {
		if exclude.pattern.MatchString(url) {
			return "", false
		}
	}
	for _, rule := range r.Rules {
		if rule.from.MatchString(url) {
			return rule.from.ReplaceAllString(url, rule.To), true
		}
	}
	return "", false
}
