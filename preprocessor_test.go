package httpseverywhere

import (
	"bytes"
	"encoding/gob"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeTo(t *testing.T) {
	to := "https://secure$1.prositehosting.co.uk/"
	expected := "https://secure${1}.prositehosting.co.uk/"
	assert.Equal(t, expected, Preprocessor.normalizeTo(to))

	to = "https://secure$20.prositehosting.co.uk/"
	expected = "https://secure${20}.prositehosting.co.uk/"
	assert.Equal(t, expected, Preprocessor.normalizeTo(to))
}

func TestPreprocessor(t *testing.T) {
	// We serialize and deserialize here to make sure that process is working and
	// also that preprocessing operations like correcting the To matching rules
	// are working correctly.
	Preprocessor.preprocess("test", "test/test-gob.gob")

	data, _ := ioutil.ReadFile("test/test-gob.gob")
	buf := bytes.NewBuffer(data)

	dec := gob.NewDecoder(buf)
	rulesets := make([]*Ruleset, 0)
	err := dec.Decode(&rulesets)
	assert.Nil(t, err)

	assert.True(t, len(rulesets) > 50)

	correctTos := 0
	badTos := 0
	for _, rs := range rulesets {
		for _, r := range rs.Rule {
			if strings.Contains(r.To, "${1}") {
				correctTos++
			}
			if strings.Contains(r.To, "$1") {
				badTos++
			}
		}
	}

	Preprocessor.log.Debugf("Correct tos: %v", correctTos)
	assert.True(t, correctTos > 0)
	assert.Equal(t, 0, badTos)
}
