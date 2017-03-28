package httpseverywhere

import (
	"bytes"
	"encoding/gob"
	"regexp"
	"time"

	"github.com/getlantern/golog"
)

type deserializer struct {
	log golog.Logger
}

func newDeserializer() *deserializer {
	return &deserializer{
		log: golog.LoggerFor("httpseverywhere-deserializer"),
	}
}

func (d *deserializer) newHostsToTargets() map[string]*Targets {
	start := time.Now()
	data := MustAsset("targets.gob")
	buf := bytes.NewBuffer(data)

	dec := gob.NewDecoder(buf)
	hostsToTargets := make(map[string]*Targets)
	err := dec.Decode(&hostsToTargets)
	if err != nil {
		d.log.Errorf("Could not decode: %v", err)
		return nil
	}
	d.log.Debugf("Loaded HTTPS Everywhere in %v", time.Now().Sub(start).String())

	// The compiled regular expressions aren't serialized, so we have to manually
	// compile them.
	for _, v := range hostsToTargets {
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
				d.log.Debugf("Error compiling? %v", err)
			} else {
				v.wildcardPrefix = append(v.wildcardPrefix, comp)
			}
		}

		v.wildcardSuffix = make([]*regexp.Regexp, 0)
		for suff := range v.WildcardSuffix {
			comp, err := regexp.Compile(suff)
			if err != nil {
				d.log.Debugf("Error compiling suffix, %v", err)
			} else {
				v.wildcardSuffix = append(v.wildcardSuffix, comp)
			}
		}
	}
	return hostsToTargets
}
