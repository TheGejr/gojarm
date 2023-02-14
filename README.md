# GoJARM

GoJARM is an implementation of [JARM](https://github.com/salesforce/jarm) in Go.

## Usage
The usage is very simple, below is an example of how to get started
```go
package main

import (
	"fmt"

	"github.com/TheGejr/gojarm"
)

func main() {
	target := gojarm.Target{
		Host: "github.com",
		Port: 443,
		Retries: 5,
	}

	res := gojarm.Fingerprint(target)

  if res.Error != nil {
    fmt.Println(res.Error)
  }

	fmt.Printf("Domain: %s\n", res.Target.Host)
  fmt.Printf("JARM: %s\n", res.Hash)
}
```

## Known errors
Currently there is some errors with the implementation, so it *shouldn't* be used in production yet.
Running the official implentation on the `alexa500.txt` provided in [JARM](https://github.com/salesforce/jarm) and running `gojarm` on the same list produces a diffrent JARM hash for 14 domains.

```diff
38c38
< ask.com,29d29d00029d29d00041d43d00041d2aa5ce6a70de7ba95aef77a77b00a0af
---
> ask.com,29d29d00029d29d00041d41d00041d2aa5ce6a70de7ba95aef77a77b00a0af
40c40
< asus.com,2ad2ad00000000000042d42d00042dd447d91fe016bed8880c9dd89d6ff72f
---
> asus.com,2ad2ad00000000000042d00000042d7698d3dd3eb4c696067118e79a0e7aff
47c47
< behance.net,29d29d00029d29d00042d43d0000002059a3b916699461c5923779b77cf06b
---
> behance.net,29d29d00029d29d00042d42d0000002059a3b916699461c5923779b77cf06b
80c80
< cnnic.cn,2ad2ad20d2ad2ad21c29d29d29d2ad75280d71138d9154efb93d30d9f6f992
---
> cnnic.cn,2ad2ad20d2ad29d00029d29d29d29d74ae70eeff52fde1275077042d423ad0
91c91
< dbs.com.sg,16d2ad16d26d26d00042d43d0000001ae0802418786940cae38f1d9eed5b9b
---
> dbs.com.sg,16d2ad16d26d26d00042d43d00000009ea392105eb6f17b86157f63a86cda5
107c107
< eastday.com,21d19d00021d21d21c21d19d21d21d62255464b56ebc756cefd18c101d5eff
---
> eastday.com,21d19d00021d21d21c21d19d21d21db8dd74e563871d5c1e91fc39148d8507
282c283
< naukri.com,28d28d28d2ad28d00042d42d000000ddf24ac27c940ce4e946c6a258c784fb
---
> naukri.com,00000028d2ad28d00042d42d000000228f1c26f7321432f107ac9bc8dc8741
316c317
< pinterest.com,29d29d00029d29d21c42d43d00041df91fb4cca79399d20b5c66084471e7db
---
> pinterest.com,29d29d00029d29d21c42d41d00041df91fb4cca79399d20b5c66084471e7db
334c335
< redd.it,29d29d00029d29d00042d41d00041d2aa5ce6a70de7ba95aef77a77b00a0af
---
> redd.it,29d29d00029d29d00042d43d00041d2aa5ce6a70de7ba95aef77a77b00a0af
361c363
< slideshare.net,29d29d00029d29d00042d43d00041d2aa5ce6a70de7ba95aef77a77b00a0af
---
> slideshare.net,29d29d00029d29d00042d43d0000002059a3b916699461c5923779b77cf06b
392c395
< theguardian.com,29d29d00029d29d00042d43d00041d2aa5ce6a70de7ba95aef77a77b00a0af
---
> theguardian.com,29d29d00029d29d00042d42d0000002059a3b916699461c5923779b77cf06b
409c412
< twitch.tv,29d29d00029d29d00042d41d00041de06ba45c86896062819edd7198001a78
---
> twitch.tv,29d29d00029d29d00041d43d00041de06ba45c86896062819edd7198001a78
423c426
< w3schools.com,29d29d00029d29d00029d29d29d29db545cd4fa73fa565f718b8a9415d8ce4
---
> w3schools.com,29d29d00029d29d00029d29d29d29dc9147433fcdc45c2dc81d2e276657a95
434c437
< wikihow.com,29d29d00029d29d00042d42d0000002059a3b916699461c5923779b77cf06b
---
> wikihow.com,29d29d00029d29d00042d42d00041d2aa5ce6a70de7ba95aef77a77b00a0af

```