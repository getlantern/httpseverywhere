package httpseverywhere

import (
	"bytes"
	"encoding/gob"
	"regexp"
	"time"

	"github.com/getlantern/golog"
	"github.com/getlantern/tldextract"
)

var (
	log     = golog.LoggerFor("httpseverywhere")
	extract = tldextract.New()
)

// Rewrite exports the rewrite method for users of this library.
var Rewrite = new()

// rewrite changes an HTTP URL to rewrite.
type rewrite func(url string) (string, bool)

//type domainRoot string

type https struct {
	log     golog.Logger
	targets map[string]*Targets
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

// new creates a new rewrite instance from embedded GOB data.
func new() rewrite {
	start := time.Now()
	data := MustAsset("targets.gob")
	buf := bytes.NewBuffer(data)

	dec := gob.NewDecoder(buf)
	targets := make(map[string]*Targets)
	err := dec.Decode(&targets)
	if err != nil {
		log.Errorf("Could not decode: %v", err)
		return nil
	}
	log.Debugf("Loaded HTTPS Everywhere in %v", time.Now().Sub(start).String())

	// The compiled regular expressions aren't serialized, so we have to manually
	// compile them.
	for _, v := range targets {
		for _, r := range v.Rules.Rules {
			r.from, _ = regexp.Compile(r.From)
		}

		for _, e := range v.Rules.Exclusions {
			e.pattern, _ = regexp.Compile(e.Pattern)
		}

		v.wildcardPrefix = make([]*regexp.Regexp, 0)
		for pre := range v.WildcardPrefix {
			comp, err := regexp.Compile(pre)
			if err != nil {
				v.wildcardPrefix = append(v.wildcardPrefix, comp)
			}
		}

		v.wildcardSuffix = make([]*regexp.Regexp, 0)
		for suff := range v.WildcardSuffix {
			comp, err := regexp.Compile(suff)
			if err != nil {
				v.wildcardSuffix = append(v.wildcardSuffix, comp)
			}
		}
	}
	return newRewrite(targets)
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

	for _, pre := range t.wildcardPrefix {
		if pre.MatchString(url) {
			return t.Rules.rewrite(url)
		}
	}

	for _, suff := range t.wildcardSuffix {
		log.Debugf("Checking %v against %v", url, suff.String())
		if suff.MatchString(url) {
			log.Debugf("Rewriting %v with %v", url, suff.String())
			return t.Rules.rewrite(url)
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
			log.Debugf("Rewriting with rules from:\n%v\n to:\n %v\nfor URL:\n"+url, rule.From, rule.To)
			return rule.from.ReplaceAllString(url, rule.To), true
		}
	}
	return url, false
}

func newRewrite(targets map[string]*Targets) rewrite {
	return (&https{log: log, targets: targets}).rewrite
}

func (h *https) rewrite(urlStr string) (string, bool) {
	result := extract.Extract(urlStr)

	domain := result.Root + "." + result.Tld
	log.Debugf("Checking domain %v", result.Root)
	//var dr domainRoot = result.Root
	if targets, ok := h.targets[result.Root]; ok {
		return targets.rewrite(urlStr, domain)
	}
	return urlStr, false
}
