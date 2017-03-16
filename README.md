# httpseverywhere
Go implementation of using HTTPS Everywhere rule sets to send traffic over HTTPS.

Example usage:

```go
import "github.com/getlantern/httpseverywhere"

...

httpURL := "http://name.com"
https, err := httpseverywhere.New()
if err != nil {
	log.Errorf("Could not load HTTPS Everywhere? %v", err)
	return
}
httpsURL, changed := https(httpURL)
if changed {
	// Redirect to httpsURL 
	...
}
```
