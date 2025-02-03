# Cloud-Verify

## Overview

Cloud-Verify is a Go library that provides cryptographic attestation to verify if your application is running within a cloud environment. It supports multiple cloud providers and is easy to integrate into your existing Go applications.

## Supported Cloud Providers

Cloud-Verify currently supports the following cloud providers:

- [Amazon Web Services (AWS)](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-pkcs7.html)
- [Microsoft Azure](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service?tabs=linux#sample-1-validate-that-the-vm-is-running-in-azure)
- [Google Cloud Platform (GCP)](https://cloud.google.com/compute/docs/instances/verifying-instance-identity)

## Prerequisites

For AWS and Azure, ensure that the `openssl` binary is installed and available in your system's `PATH`. This prerequisite is not required for GCP.

## How to Use

Here is a simple example of how to use Cloud-Verify in your Go application:

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

### Updating AWS Certificates

Cloud-Verify uses the certificates present at https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/regions-certs.html to validate AWS metadata.

In case those need to be updated and I haven't done so yet, you can update them manually by running the following command:

```bash
go run cmd/update-certs/main.go
```

## License

This project is licensed under the MIT License.
