package httpseverywhere

import (
	"testing"

	"github.com/getlantern/golog"
	"github.com/stretchr/testify/assert"
)

func TestNewFromGOB(t *testing.T) {
	h, err := NewDefault()
	assert.Nil(t, err)

	base := "http://name.com"
	r, mod := h(base)

	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://name.com", r)

	base = "http://support.name.com"
	r, mod = h(base)

	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://support.name.com", r)
}

func TestNewFromGOBFile(t *testing.T) {
	h, err := NewFromGOBFile("test/test-targets.gob")
	assert.Nil(t, err)

	base := "http://name.com"
	r, mod := h(base)

	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://name.com", r)

	base = "http://support.name.com"
	r, mod = h(base)

	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://support.name.com", r)
}

func TestAddAllRules(t *testing.T) {
	h := AddAllRules("./testrules")

	base := "http://name.com"
	r, mod := h.ToHTTPS(base)

	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://name.com", r)

	base = "http://support.name.com"
	r, mod = h.ToHTTPS(base)

	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://support.name.com", r)
}

func BenchmarkAddAllRules(t *testing.B) {
	//log := golog.LoggerFor("httpseverywhere_test")

	AddAllRules("./testrules")
}

func BenchmarkNoMatch(b *testing.B) {
	h, err := NewDefault()
	if err != nil {
		b.Fatal(err)
	}

	url := "http://unknowndomainthatshouldnotmatch.com"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h(url)
	}
}

/*
func main() {
	br := testing.Benchmark(BenchmarkAddAllRules)
	fmt.Println(br)
}
*/

// Test for the mixed content flag. Because we don't run on any platform that
// supports mixed content, the flag essentially means the rule is turned off.
func TestMixedContent(t *testing.T) {
	var testRule = `<ruleset name="RabbitMQ" platform="mixedcontent">
        <target host="rabbitmq.com" />
        <target host="www.rabbitmq.com" />

        <rule from="^http:"
                to="https:" />
</ruleset>`

	h := NewFromRule(testRule)
	base := "http://rabbitmq.com"
	r, mod := h.ToHTTPS(base)

	assert.False(t, mod, "should NOT have been modified to https")
	assert.Equal(t, "http://rabbitmq.com", r)

	base = "http://www.rabbitmq.com"
	r, mod = h.ToHTTPS(base)

	assert.False(t, mod, "should NOT have been modified to https")
	assert.Equal(t, "http://www.rabbitmq.com", r)
}

func TestIgnoreHTTPRedirect(t *testing.T) {
	var testRule = `<ruleset name="SO">

				<target host="stackoverflow.com" />
				<rule from="^https:"
								to="http:" />
</ruleset>`

	h := NewFromRule(testRule)
	base := "https://stackoverflow.com/users/authenticate/"
	r, mod := h.ToHTTPS(base)

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

	h := NewFromRule(testRule)
	base := "http://stackoverflow.com/users/authenticate/"
	r, mod := h.ToHTTPS(base)

	assert.False(t, mod, "should NOT have been modified to https")
	assert.Equal(t, "http://stackoverflow.com/users/authenticate/", r)

	// Test when we don't match the exclusion string.
	base = "http://stackoverflow.com/users/"
	r, mod = h.ToHTTPS(base)

	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://stackoverflow.com/users/", r)

	// Test when we don't match the exclusion string or any rules
	base = "https://stackoverflow.com/users/"
	r, mod = h.ToHTTPS(base)

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

	h := NewFromRule(testRule)
	base := "http://rabbitmq.com"
	r, mod := h.ToHTTPS(base)

	assert.False(t, mod, "should NOT have been modified to https")
	assert.Equal(t, "http://rabbitmq.com", r)

	base = "http://www.rabbitmq.com"
	r, mod = h.ToHTTPS(base)

	assert.False(t, mod, "should NOT have been modified to https")
	assert.Equal(t, "http://www.rabbitmq.com", r)

}

func TestComplex(t *testing.T) {
	var testRule = `<ruleset name="Wikipedia">
  <target host="*.wikipedia.org" />

  <rule from="^http://(\w{2})\.wikipedia\.org/wiki/"
          to="https://secure.wikimedia.org/wikipedia/$1/wiki/"/>
</ruleset>`
	h := NewFromRule(testRule)
	base := "http://fr.wikipedia.org/wiki/Chose"
	r, mod := h.ToHTTPS(base)

	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://secure.wikimedia.org/wikipedia/fr/wiki/Chose", r)
}

func TestMultipleTargets(t *testing.T) {
	var testRule = `<ruleset name="RabbitMQ">
        <target host="rabbitmq.com" />
        <target host="www.rabbitmq.com" />

        <rule from="^http:"
                to="https:" />
</ruleset>`

	h := NewFromRule(testRule)
	base := "http://rabbitmq.com"
	r, mod := h.ToHTTPS(base)

	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://rabbitmq.com", r)

	base = "http://www.rabbitmq.com"
	r, mod = h.ToHTTPS(base)

	assert.True(t, mod, "should have been modified to https")
	assert.Equal(t, "https://www.rabbitmq.com", r)
}

func TestRedirect(t *testing.T) {
	log := golog.LoggerFor("httpseverywhere_test")

	var testRule = `<ruleset name="Bundler.io">
		<target host="bundler.io"/>
		<rule from="^http:" to="https:" />
	</ruleset>`
	h := NewFromRule(testRule)
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
	base := "subdomain.bundler.io"
	stripped := stripSubdomains(base)
	assert.Equal(t, "bundler.io", stripped)

	base = "bundler.io"
	stripped = stripSubdomains(base)
	assert.Equal(t, "bundler.io", stripped)

	base = "bundler.a.io"
	stripped = stripSubdomains(base)

	assert.Equal(t, "a.io", stripped)

	base = "a.b.io"
	stripped = stripSubdomains(base)

	assert.Equal(t, "b.io", stripped)

	base = "a.b.c.com"
	stripped = stripSubdomains(base)

	assert.Equal(t, "c.com", stripped)
}

func TestWildcardPrefix(t *testing.T) {
	var rule = `<ruleset name="Bundler.io">
		<target host="*.bundler.io"/>
		<rule from="^http:" to="https:" />
	</ruleset>`
	h := NewFromRule(rule)
	base := "http://subdomain.bundler.io"
	r, mod := h.ToHTTPS(base)

	assert.True(t, mod)
	assert.Equal(t, "https://subdomain.bundler.io", r)
}

func TestWildcardSuffix(t *testing.T) {
	var rule = `<ruleset name="Bundler.io">
		<target host="bundler.*"/>
		<rule from="^http:" to="https:" />
	</ruleset>`
	h := NewFromRule(rule)
	base := "http://bundler.io"
	r, mod := h.ToHTTPS(base)

	assert.True(t, mod)
	assert.Equal(t, "https://bundler.io", r)
}
