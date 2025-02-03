package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

const (
	awsCertsURL      = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/regions-certs.html"
	outputDir        = "aws/certs"
	targetCertType   = "DSA"
	headerAttribute  = "header"
	layoutStart      = "-----BEGIN CERTIFICATE-----"
	layoutEnd        = "-----END CERTIFICATE-----"
	contentSelector  = "awsui-expandable-section"
	tabContentSelect = "dl"
)

func main() {
	err := os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		log.Fatalf("Failed to create output directory %s: %v", outputDir, err)
	}

	resp, err := http.Get(awsCertsURL)
	if err != nil {
		log.Fatalf("Error fetching URL %s: %v", awsCertsURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Fatalf("Failed to fetch URL %s: Status code %d", awsCertsURL, resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		log.Fatalf("Error loading HTTP response body: %v", err)
	}

	doc.Find(contentSelector).Each(func(i int, s *goquery.Selection) {
		// Extract the header text which contains the region name and code
		header, exists := s.Attr(headerAttribute)
		if !exists {
			log.Println("Expandable section without header attribute found. Skipping.")
			return
		}

		// Extract the region code from the header
		regionCode := extractRegionCode(header)
		if regionCode == "" {
			log.Printf("Could not extract region code from header: %s. Skipping.\n", header)
			return
		}

		dl := s.Find(tabContentSelect)
		if dl.Length() == 0 {
			log.Printf("No definition list found in section for region %s. Skipping.\n", regionCode)
			return
		}

		dl.Find("dt").Each(func(j int, dt *goquery.Selection) {
			term := strings.TrimSpace(dt.Text())
			if term != targetCertType {
				return
			}

			dd := dt.NextFiltered("dd")
			if dd.Length() == 0 {
				log.Printf("No definition data found for term '%s' in region %s. Skipping.\n", term, regionCode)
				return
			}

			certContent, err := extractCertificate(dd.Text())
			if err != nil {
				log.Printf("Error extracting certificate for region %s: %v. Skipping.\n", regionCode, err)
				return
			}

			outputPath := filepath.Join(outputDir, fmt.Sprintf("%s.pem", regionCode))

			err = os.WriteFile(outputPath, []byte(certContent), 0644)
			if err != nil {
				log.Printf("Failed to write certificate to %s: %v\n", outputPath, err)
				return
			}

			log.Printf("Successfully wrote DSA certificate for region %s to %s\n", regionCode, outputPath)
		})
	})

	log.Println("Certificate extraction completed.")
}

// extractRegionCode parses the header to extract the region code (e.g., "us-east-1")
func extractRegionCode(header string) string {
	parts := strings.Split(header, "—")
	if len(parts) != 2 {
		return ""
	}

	return strings.TrimSpace(parts[1])
}

// extractCertificate extracts the certificate block from the provided text
func extractCertificate(text string) (string, error) {
	start := strings.Index(text, layoutStart)
	end := strings.Index(text, layoutEnd)

	if start == -1 || end == -1 {
		return "", fmt.Errorf("certificate delimiters not found")
	}

	// Include the BEGIN and END delimiters
	cert := text[start : end+len(layoutEnd)]
	cert = strings.TrimSpace(cert)
	lines := strings.Split(cert, "\n")
	cleanLines := []string{}
	for _, line := range lines {
		cleanLine := strings.TrimSpace(line)
		if cleanLine != "" {
			cleanLines = append(cleanLines, cleanLine)
		}
	}
	return strings.Join(cleanLines, "\n"), nil
}
