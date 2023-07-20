package cloudverify

import (
	"sync"
	"time"

	"github.com/kamushadenes/cloud-verify/aws"
	"github.com/kamushadenes/cloud-verify/azure"
	"github.com/kamushadenes/cloud-verify/gcp"
)

type cloudVerification struct {
	Name           string
	RunningOnCloud bool
}

func RunningOnCloud() (bool, string) {
	var ch = make(chan *cloudVerification)
	var waitCh = make(chan bool)

	var wg sync.WaitGroup

	wg.Add(1)
	go func(ch chan *cloudVerification) {
		defer wg.Done()

		awsv := aws.NewAWSVerifier()

		ch <- &cloudVerification{
			Name:           "AWS",
			RunningOnCloud: awsv.Verify(),
		}
	}(ch)

	wg.Add(1)
	go func(ch chan *cloudVerification) {
		defer wg.Done()

		gcpv := gcp.NewGCPVerifier()

		ch <- &cloudVerification{
			Name:           "GCP",
			RunningOnCloud: gcpv.Verify(),
		}
	}(ch)

	wg.Add(1)
	go func(ch chan *cloudVerification) {
		defer wg.Done()

		azurev := azure.NewAzureVerifier()

		ch <- &cloudVerification{
			Name:           "Azure",
			RunningOnCloud: azurev.Verify(),
		}
	}(ch)

	go func() {
		wg.Wait()
		time.Sleep(200 * time.Millisecond)
		close(waitCh)
	}()

	for {
		select {
		case v := <-ch:
			if v.RunningOnCloud {
				return true, v.Name
			}
		case <-waitCh:
			return false, "Not Detected"
		case <-time.After(5 * time.Second):
			return false, "Timeout"
		}
	}
}
