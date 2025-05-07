# OOPSpam Go Client

A Go client library for interacting with the OOPSpam API. This client provides easy access to spam detection, domain reputation checking, and spam reporting functionality.

## Installation

```bash
go get github.com/ready4god2513/oopspam
```

## Usage

### Creating a Client

```go
import "github.com/ready4god2513/oopspam"

// Create a new client with your API key
client := oopspam.NewClient("your-api-key", &http.Client{})
```

### Checking for Spam

```go
// Create a spam detection request
req := &oopspam.SpamDetectionRequest{
    SenderIP: "91.203.67.110",
    Email:    "testing@example.com",
    Content:  "Your message content here",
    CheckForLength: true,
    AllowedLanguages: []string{"en"},
    AllowedCountries: []string{"us", "ca"},
}

// Check if the content is spam
response, err := client.CheckSpam(req)
if err != nil {
    log.Fatal(err)
}

// Check the spam score (3 or higher is considered spam)
if response.Score >= 3 {
    fmt.Println("This is spam!")
} else {
    fmt.Println("This is not spam.")
}

// Access detailed information
fmt.Printf("IP Blocked: %v\n", response.Details.IsIPBlocked)
fmt.Printf("Email Blocked: %v\n", response.Details.IsEmailBlocked)
fmt.Printf("Number of Spam Words: %d\n", response.Details.NumberOfSpamWords)
```

### Checking Domain Reputation

```go
// Check domain reputation
response, err := client.CheckDomainReputation("example.com")
if err != nil {
    log.Fatal(err)
}

if response.Blocked {
    fmt.Printf("Domain is blocked by: %v\n", response.Blocker)
} else {
    fmt.Println("Domain is not blocked")
}
```

### Reporting False Positives/Negatives

```go
// Create a spam detection request
req := &oopspam.SpamDetectionRequest{
    SenderIP: "91.203.67.110",
    Email:    "testing@example.com",
    Content:  "Your message content here",
}

// Report a false positive (content was marked as spam but shouldn't be)
err := client.ReportSpam(req, false)
if err != nil {
    log.Fatal(err)
}
```

## API Documentation

The client implements the following endpoints from the OOPSpam API:

1. Spam Detection (`/spamdetection`)
2. Domain Reputation (`/reputation/domain`)
3. Spam Reporting (`/spamdetection/report`)

For more detailed API documentation, visit [OOPSpam API Documentation](https://www.oopspam.com/docs/?go#spam-detection).

## Error Handling

The client returns detailed error messages when API calls fail. All errors include the HTTP status code and response body when available.

## Rate Limiting

The client respects the rate limits set by the OOPSpam API. Make sure to handle rate limit errors appropriately in your application.

## License

MIT License 