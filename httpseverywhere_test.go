package httpseverywhere

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewFromGOB(t *testing.T) {
	h := new()

	base := "http://name.com"
	r, mod := h(base)

	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://name.com", r)

	base = "http://support.name.com"
	r, mod = h(base)

	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://support.name.com", r)
}

func TestLinkedIn(t *testing.T) {
	h := new()

	base := "http://platform.linkedin.com/"
	r, mod := h(base)

	assert.True(t, mod)
	assert.Equal(t, "https://platform.linkedin.com/", r)
}

// Test for the mixed content flag. Because we don't run on any platform that
// supports mixed content, the flag essentially means the rule is turned off.
func TestMixedContent(t *testing.T) {
	var testRule = `<ruleset name="RabbitMQ" platform="mixedcontent">
        <target host="rabbitmq.com" />
        <target host="www.rabbitmq.com" />

        <rule from="^http:"
                to="https:" />
</ruleset>`

	h, _ := newHTTPS(testRule)
	base := "http://rabbitmq.com"
	r, mod := h(base)

	assert.False(t, mod, "should NOT have been modified to https")
	assert.Equal(t, "http://rabbitmq.com", r)

	base = "http://www.rabbitmq.com"
	r, mod = h(base)

	assert.False(t, mod, "should NOT have been modified to https")
	assert.Equal(t, "http://www.rabbitmq.com", r)
}

func TestIgnoreHTTPRedirect(t *testing.T) {
	var testRule = `<ruleset name="SO">

				<target host="stackoverflow.com" />
				<rule from="^https:"
								to="http:" />
</ruleset>`

	h, _ := newHTTPS(testRule)
	base := "https://stackoverflow.com/users/authenticate/"
	r, mod := h(base)

	assert.False(t, mod, "should NOT have been modified FROM https")
	assert.Equal(t, "https://stackoverflow.com/users/authenticate/", r)

}

func TestExclusions(t *testing.T) {
	var testRule = `<ruleset name="SO">

				<target host="stackoverflow.com" />

				<exclusion pattern="^http://(?:\w+\.)?stack(?:exchange|overflow)\.com/users/authenticate/" />
				<rule from="^http:"
								to="https:" />
</ruleset>`

	h, _ := newHTTPS(testRule)
	base := "http://stackoverflow.com/users/authenticate/"
	r, mod := h(base)

	assert.False(t, mod, "should NOT have been modified to https")
	assert.Equal(t, "http://stackoverflow.com/users/authenticate/", r)

	// Test when we don't match the exclusion string.
	base = "http://stackoverflow.com/users/"
	r, mod = h(base)

	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://stackoverflow.com/users/", r)

	// Test when we don't match the exclusion string or any rules
	base = "https://stackoverflow.com/users/"
	r, mod = h(base)

	assert.False(t, mod, "already HTTPS")
	assert.Equal(t, "https://stackoverflow.com/users/", r)
}

func TestDefaultOff(t *testing.T) {
	var testRule = `<ruleset name="RabbitMQ" default_off="just cuz">
        <target host="rabbitmq.com" />
        <target host="www.rabbitmq.com" />

        <rule from="^http:"
                to="https:" />
</ruleset>`

	h, _ := newHTTPS(testRule)
	base := "http://rabbitmq.com"
	r, mod := h(base)

	assert.False(t, mod, "should NOT have been modified to https")
	assert.Equal(t, "http://rabbitmq.com", r)

	base = "http://www.rabbitmq.com"
	r, mod = h(base)

	assert.False(t, mod, "should NOT have been modified to https")
	assert.Equal(t, "http://www.rabbitmq.com", r)

}

func TestComplex(t *testing.T) {
	var testRule = `<ruleset name="Wikipedia">
  <target host="*.wikipedia.org" />

  <rule from="^http://(\w{2})\.wikipedia\.org/wiki/"
          to="https://secure.wikimedia.org/wikipedia/$1/wiki/"/>
</ruleset>`
	h, _ := newHTTPS(testRule)
	base := "http://fr.wikipedia.org/wiki/Chose"
	r, mod := h(base)

	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://secure.wikimedia.org/wikipedia/fr/wiki/Chose", r)
}

func TestMultipleTargets(t *testing.T) {
	var testRule = `<ruleset name="RabbitMQ">
        <target host="rabbitmq.com" />
        <target host="www.rabbitmq.com" />
				<target host="rabbitmq.*" />

        <rule from="^http:"
                to="https:" />
</ruleset>`

	h, _ := newHTTPS(testRule)
	base := "http://rabbitmq.com"
	r, mod := h(base)

	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://rabbitmq.com", r)

	base = "http://www.rabbitmq.com"
	r, mod = h(base)

	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://www.rabbitmq.com", r)

	base = "http://rabbitmq.net"
	r, mod = h(base)

	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://rabbitmq.net", r)
}

func TestIgnoreMultipleSubdomains(t *testing.T) {
	var testRule = `<ruleset name="RabbitMQ">
        <target host="*.b.rabbitmq.com" />

        <rule from="^http:"
                to="https:" />
</ruleset>`

	h, _ := newHTTPS(testRule)
	base := "http://rabbitmq.com"
	r, mod := h(base)

	assert.False(t, mod, "should NOT have been modified to https")
	assert.Equal(t, "http://rabbitmq.com", r)
}

func TestDuplicateTargets(t *testing.T) {
	var testRule = `<ruleset name="RabbitMQ">
        <target host="rabbitmq.com" />

        <rule from="^http:"
                to="https:" />
</ruleset>`

	h, targets := newHTTPS(testRule)
	base := "http://rabbitmq.com"
	r, mod := h(base)

	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://rabbitmq.com", r)

	// Now add another ruleset with the same target.
	processed := Preprocessor.AddRuleSet([]byte(testRule), targets)
	assert.True(t, processed, "should have been considered processed")
}

func TestSimple(t *testing.T) {
	var testRule = `<ruleset name="Bundler.io">
		<target host="bundler.io"/>
		<rule from="^http:" to="https:" />
	</ruleset>`
	h, _ := newHTTPS(testRule)
	base := "http://bundler.io"
	r, mod := h(base)

	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://bundler.io", r)
}

func TestWildcardPrefix(t *testing.T) {
	var rule = `<ruleset name="Bundler.io">
		<target host="*.bundler.io"/>
		<rule from="^http:" to="https:" />
	</ruleset>`
	h, _ := newHTTPS(rule)
	base := "http://subdomain.bundler.io"
	r, mod := h(base)

	assert.True(t, mod)
	assert.Equal(t, "https://subdomain.bundler.io", r)
}

func TestWildcardSuffix(t *testing.T) {
	var rule = `<ruleset name="Bundler.io">
		<target host="bundler.*"/>
		<rule from="^http:" to="https:" />
	</ruleset>`
	h, _ := newHTTPS(rule)
	base := "http://bundler.io"
	r, mod := h(base)

	assert.True(t, mod)
	assert.Equal(t, "https://bundler.io", r)
}

// newHTTPS creates a new rewrite instance from a single rule set string. In
// practice this is used for testing.
func newHTTPS(rules string) (rewrite, map[string]*Targets) {
	targets := make(map[string]*Targets)
	Preprocessor.AddRuleSet([]byte(rules), targets)
	return newRewrite(targets), targets
}
