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
