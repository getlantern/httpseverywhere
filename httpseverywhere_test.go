package httpseverywhere

import (
	"testing"

	//"github.com/Sirupsen/logrus"
	"github.com/getlantern/golog"
	"github.com/stretchr/testify/assert"
)

func TestRedirect(t *testing.T) {
	log := golog.LoggerFor("httpseverywhere_test")

	var testRule = `<ruleset name="Bundler.io">
		<target host="bundler.io"/>
		<rule from="^http:" to="https:" />
	</ruleset>`
	h := NewHTTPS(testRule)
	base := "http://bundler.io"
	r, mod := h.ToHTTPS(base)

	log.Debugf("New: %v", r)
	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://bundler.io", r)
}

func TestStripTLD(t *testing.T) {
	base := "bundler.io"
	stripped := stripTLD(base)
	assert.Equal(t, "bundler.", stripped)
}

func TestStripSubdomain(t *testing.T) {
	log := golog.LoggerFor("httpseverywhere_test")

	base := "subdomain.bundler.io"
	stripped := stripSubdomains(base)
	assert.Equal(t, "bundler.io", stripped)

	base = "bundler.io"
	stripped = stripSubdomains(base)
	assert.Equal(t, "bundler.io", stripped)

	base = "bundler.a.io"
	stripped = stripSubdomains(base)

	log.Debugf("Got: %v", stripped)
	assert.Equal(t, "a.io", stripped)

	base = "a.b.io"
	stripped = stripSubdomains(base)

	log.Debugf("Got: %v", stripped)
	assert.Equal(t, "b.io", stripped)

	base = "a.b.c.com"
	stripped = stripSubdomains(base)

	log.Debugf("Got: %v", stripped)
	assert.Equal(t, "c.com", stripped)
}

func TestWildcardPrefix(t *testing.T) {
	log := golog.LoggerFor("httpseverywhere_test")

	var rule = `<ruleset name="Bundler.io">
		<target host="*.bundler.io"/>
		<rule from="^http:" to="https:" />
	</ruleset>`
	h := NewHTTPS(rule)
	base := "http://subdomain.bundler.io"
	r, mod := h.ToHTTPS(base)

	log.Debugf("New: %v", r)
	assert.True(t, mod)
	assert.Equal(t, "https://subdomain.bundler.io", r)
}

func TestWildcardSuffix(t *testing.T) {
	log := golog.LoggerFor("httpseverywhere_test")

	var rule = `<ruleset name="Bundler.io">
		<target host="bundler.*"/>
		<rule from="^http:" to="https:" />
	</ruleset>`
	h := NewHTTPS(rule)
	base := "http://bundler.io"
	r, mod := h.ToHTTPS(base)

	log.Debugf("New: %v", r)
	assert.True(t, mod)
	assert.Equal(t, "https://bundler.io", r)
}
