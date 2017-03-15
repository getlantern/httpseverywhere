package main

import (
	"bytes"
	"encoding/gob"
	"io/ioutil"
	"path/filepath"

	"github.com/getlantern/golog"
	"github.com/getlantern/httpseverywhere"
)

// Preprocess adds all of the rules in the specified directory.
func Preprocess(dir string) {
	log := golog.LoggerFor("httpseverywhere-preprocessor")
	targets := make(map[string]*httpseverywhere.Rules)
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}

	var errors int
	for _, file := range files {
		/*
			if !strings.HasPrefix(file.Name(), "Name.com") {
				continue
			}
		*/
		b, errr := ioutil.ReadFile(filepath.Join(dir, file.Name()))
		if errr != nil {
			//log.Errorf("Error reading file: %v", err)
		} else {
			if !httpseverywhere.AddRuleSet(b, targets) {
				errors++
			}
		}
	}

	log.Debugf("Loaded rules with %v targets and %v errors", len(targets), errors)
	//return &https{log: log, targets: targets}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	// Encode (send) the value.
	err = enc.Encode(targets)
	if err != nil {
		log.Fatalf("encode error: %v", err)
	}
	ioutil.WriteFile("targets.gob", buf.Bytes(), 0644)
}

func main() {
	Preprocess("./https-everywhere/src/chrome/content/rules/")
}
