# cloud-verify

## Description

Cryptographically attest if your Go application is being executed within a cloud environment.

## Supported Cloud Providers

- [Azure](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service?tabs=linux#sample-1-validate-that-the-vm-is-running-in-azure)
- [AWS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-pkcs7.html)
- [Google Cloud](https://cloud.google.com/compute/docs/instances/verifying-instance-identity)

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
