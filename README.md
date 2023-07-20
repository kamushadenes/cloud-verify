# cloud-verify

## Description

Cryptographically attest if your Go application is being executed within a cloud environment.

## Supported Cloud Providers

- AWS
- Google Cloud
- Azure

## Dependencies

You need the `openssl` binary installed and available in the `PATH`.

## Usage

```go
package main

import (
  "fmt"
  cloudverify "github.com/kamushadenes/cloud-verify"
)

func main() {
	if v, cloud := cloudverify.RunningOnCloud(); v {
		fmt.Printf("Running on Cloud (%s)\n", cloud)
	} else {
		fmt.Printf("Not running on Cloud (%s)\n", cloud)
	}
}
```

## License

This project is licensed under the MIT License.
