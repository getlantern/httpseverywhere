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

func (d *deserializer) newDomainsToRulesets() map[string]*Rules {
	start := time.Now()
	data := MustAsset("rulesets.gob")
	buf := bytes.NewBuffer(data)

	dec := gob.NewDecoder(buf)
	domainsToRulesets := make(map[string]*Rules)
	err := dec.Decode(&domainsToRulesets)
	if err != nil {
		d.log.Errorf("Could not decode: %v", err)
		return nil
	}
	d.log.Debugf("Loaded HTTPS Everywhere in %v", time.Now().Sub(start).String())

	// The compiled regular expressions aren't serialized, so we have to manually
	// compile them.
	for _, set := range domainsToRulesets {
		for _, target := range set.RegexTargets {
			target.regex, err = regexp.Compile(target.Regex)
			if err != nil {
				d.log.Debugf("Error compiling target %v? %v", target.Regex, err)
			}
		}

		for _, rule := range set.Rules {
			rule.from, err = regexp.Compile(rule.From)
			if err != nil {
				d.log.Debugf("Error compiling rule %v? %v", rule.From, err)
			}
		}

		for _, e := range set.Exclusions {
			e.pattern, err = regexp.Compile(e.Pattern)
			if err != nil {
				d.log.Debugf("Error compiling exclusion %v? %v", e.Pattern, err)
			}
		}

		/*
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
		*/
	}
	return domainsToRulesets
}
