package httpseverywhere

import (
	"testing"

	//"github.com/Sirupsen/logrus"

	"github.com/getlantern/golog"
	"github.com/stretchr/testify/assert"
)

func TestComplex(t *testing.T) {
	log := golog.LoggerFor("httpseverywhere_test")
	var testRule = `<ruleset name="Wikipedia">
  <target host="*.wikipedia.org" />

  <rule from="^http://(\w{2})\.wikipedia\.org/wiki/"
          to="https://secure.wikimedia.org/wikipedia/$1/wiki/"/>
</ruleset>`
	h := NewHTTPS(testRule)
	base := "http://fr.wikipedia.org/wiki/Chose"
	r, mod := h.ToHTTPS(base)

	log.Debugf("New: %v", r)
	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://secure.wikimedia.org/wikipedia/fr/wiki/Chose", r)
}

func TestMultipleTargets(t *testing.T) {
	log := golog.LoggerFor("httpseverywhere_test")
	var testRule = `<ruleset name="RabbitMQ">
        <target host="rabbitmq.com" />
        <target host="www.rabbitmq.com" />

        <rule from="^http:"
                to="https:" />
</ruleset>`

	h := NewHTTPS(testRule)
	base := "http://rabbitmq.com"
	r, mod := h.ToHTTPS(base)

	log.Debugf("New: %v", r)
	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://rabbitmq.com", r)

	base = "http://www.rabbitmq.com"
	r, mod = h.ToHTTPS(base)

	log.Debugf("New: %v", r)
	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://www.rabbitmq.com", r)
}

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
