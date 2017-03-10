package httpseverywhere

import (
	"testing"

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

/*
func TestWildcard(t *testing.T) {
	log := golog.LoggerFor("httpseverywhere_test")

	var rule = `<ruleset name="Bundler.io">
		<target host="*.bundler.io"/>
		<rule from="^http:" to="https:" />
	</ruleset>`
	h := NewHTTPS(rule)
	base := "http://bundler.io"
	r, mod := h.ToHTTPS(base)

	log.Debugf("New: %v", r)
	assert.True(t, mod)
	assert.Equal(t, "https://bundler.io", r)
}
*/
