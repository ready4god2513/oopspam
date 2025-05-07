package main

import (
	"fmt"
	"log"
	"os"

	"github.com/ready4god2513/oopspam"
)

func main() {
	// Get API key from environment variable
	apiKey := os.Getenv("OOPSPAM_API_KEY")
	if apiKey == "" {
		log.Fatal("OOPSPAM_API_KEY environment variable is required")
	}

	// Create a new client with default HTTP client
	client := oopspam.NewClient(apiKey, nil)

	// Example 1: Check for spam
	spamReq := &oopspam.SpamDetectionRequest{
		SenderIP:         "91.203.67.110",
		Email:            "testing@example.com",
		Content:          "Dear Agent, We are a manufacturing company which specializes in supplying Aluminum Rod with Zinc Alloy Rod to customers worldwide, based in Japan, Asia.",
		CheckForLength:   true,
		AllowedLanguages: []string{"en"},
		AllowedCountries: []string{"us", "ca"},
	}

	spamResp, err := client.CheckSpam(spamReq)
	if err != nil {
		log.Fatalf("Error checking spam: %v", err)
	}

	fmt.Println("Spam Check Results:")
	fmt.Printf("Score: %d\n", spamResp.Score)
	fmt.Printf("Is Spam: %v\n", spamResp.Score >= 3)
	fmt.Printf("IP Blocked: %v\n", spamResp.Details.IsIPBlocked)
	fmt.Printf("Email Blocked: %v\n", spamResp.Details.IsEmailBlocked)
	fmt.Printf("Number of Spam Words: %d\n", spamResp.Details.NumberOfSpamWords)
	if len(spamResp.Details.SpamWords) > 0 {
		fmt.Printf("Spam Words: %v\n", spamResp.Details.SpamWords)
	}
	fmt.Println()

	// Example 2: Check domain reputation
	domainResp, err := client.CheckDomainReputation("example.com")
	if err != nil {
		log.Fatalf("Error checking domain reputation: %v", err)
	}

	fmt.Println("Domain Reputation Results:")
	fmt.Printf("Domain Blocked: %v\n", domainResp.Blocked)
	if domainResp.Blocked {
		fmt.Printf("Blocked by: %v\n", domainResp.Blocker)
	}
	fmt.Println()

	// Example 3: Report false positive
	if spamResp.Score >= 3 {
		fmt.Println("Reporting false positive...")
		err = client.ReportSpam(spamReq, false)
		if err != nil {
			log.Fatalf("Error reporting spam: %v", err)
		}
		fmt.Println("False positive reported successfully")
	}
}
