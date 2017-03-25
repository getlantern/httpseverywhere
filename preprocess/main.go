package main

import "github.com/getlantern/httpseverywhere"

func main() {
	httpseverywhere.Preprocessor.Preprocess("./https-everywhere/src/chrome/content/rules/")
}
