# httpseverywhere
Go implementation of using HTTPS Everywhere rule sets to send traffic over HTTPS.

Example usage:

```go
import "url"
import "github.com/getlantern/httpseverywhere"

...

httpURL, _ := url.Parse("http://name.com")
httpsURL, changed := httpseverywhere.Rewrite(httpURL)
if changed {
	// Redirect to httpsURL
	...
}
```
