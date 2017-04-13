package httpseverywhere

import (
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Yawning/obfs4/common/log"
	"github.com/getlantern/golog"
	iradix "github.com/hashicorp/go-immutable-radix"
)

// Rewrite changes an HTTP URL to rewrite.
type Rewrite func(url *url.URL) (string, bool)

type httpse struct {
	log             golog.Logger
	runs            int64
	totalTime       int64
	max             int64
	maxHost         string
	statM           sync.RWMutex
	initOnce        sync.Once
	wildcardTargets atomic.Value // *iradix.Tree
	plainTargets    atomic.Value // map[string]*ruleset
}

// Default returns a lazily-initialized Rewrite using the default rules
func Default() Rewrite {
	h := newEmpty()
	h.initAsync()
	return h.rewrite
}

func newEmpty() *httpse {
	h := &httpse{
		log: golog.LoggerFor("httpse"),
	}
	h.wildcardTargets.Store(iradix.New())
	h.plainTargets.Store(make(map[string]*ruleset))
	return h
}

func (h *httpse) init() {
	d := newDeserializer()
	plain, wildcard, err := d.newRulesets()
	if err != nil {
		return
	}
	h.plainTargets.Store(plain)
	h.wildcardTargets.Store(wildcard)
}

func (h *httpse) initAsync() {
	h.initOnce.Do(func() {
		go h.init()
	})
}

func (h *httpse) rewrite(url *url.URL) (string, bool) {
	if url.Scheme != "http" {
		return "", false
	}

	start := time.Now()
	if val, ok := h.plainTargets.Load().(map[string]*ruleset)[url.Host]; ok {
		r, hit := h.rewriteWithRuleset(url, val)
		h.addTiming(time.Now().Sub(start), url.String())
		return r, hit
	}
	_, val, match := h.wildcardTargets.Load().(*iradix.Tree).Root().LongestPrefix([]byte(url.Host))
	if !match {
		h.log.Debugf("No suffix match for %v", url.Host)

		// Now check prefixes (with reversing the URL host)
		_, val, match = h.wildcardTargets.Load().(*iradix.Tree).Root().LongestPrefix([]byte(reverse(url.Host)))
	}

	if !match {
		h.log.Debugf("No match for %v", url.Host)
		return "", false
	}

	rs := val.(*ruleset)

	r, hit := h.rewriteWithRuleset(url, rs)
	h.addTiming(time.Now().Sub(start), url.String())
	return r, hit
}

// rewriteWithRuleset converts the given URL to HTTPS if there is an associated
// rule for it.
func (h *httpse) rewriteWithRuleset(fullURL *url.URL, r *ruleset) (string, bool) {
	url := fullURL.String()
	for _, exclude := range r.exclusion {
		if exclude.pattern.MatchString(url) {
			return "", false
		}
	}
	for _, rule := range r.rule {
		if rule.from.MatchString(url) {
			return rule.from.ReplaceAllString(url, rule.to), true
		}
	}
	return "", false
}

func reverse(input string) string {
	n := 0
	runes := make([]rune, len(input)+1)
	// Add a dot prefix to make sure we're only operating on subdomains
	runes[0] = '.'
	runes = runes[1:]
	for _, r := range input {
		runes[n] = r
		n++
	}
	runes = runes[0:n]
	// Reverse
	for i := 0; i < n/2; i++ {
		runes[i], runes[n-1-i] = runes[n-1-i], runes[i]
	}
	// Convert back to UTF-8.
	return string(runes)
}

func (h *httpse) addTiming(dur time.Duration, host string) {
	ms := dur.Nanoseconds() / int64(time.Millisecond)
	h.statM.Lock()
	h.runs++
	h.totalTime += ms
	if ms > h.max {
		h.max = ms
		h.maxHost = host
	}
	h.statM.Unlock()

	h.statM.RLock()
	log.Debugf("Average running time: %vms", float64(h.totalTime/h.runs))
	log.Debugf("Max running time: %vms for host: %v", h.max, h.maxHost)
	h.statM.RUnlock()
}
