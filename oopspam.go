package oopspam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const (
	// BaseURL is the base URL for the OOPSpam API
	BaseURL = "https://api.oopspam.com/v1"
)

// Client represents an OOPSpam API client
type Client struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string
}

// NewClient creates a new OOPSpam API client
func NewClient(apiKey string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &Client{
		apiKey:     apiKey,
		httpClient: httpClient,
		baseURL:    BaseURL,
	}
}

// SpamDetectionRequest represents the request body for spam detection
type SpamDetectionRequest struct {
	SenderIP         string   `json:"senderIP"`
	Email            string   `json:"email"`
	Content          string   `json:"content"`
	BlockTempEmail   bool     `json:"blockTempEmail,omitempty"`
	BlockVPN         bool     `json:"blockVPN,omitempty"`
	BlockDC          bool     `json:"blockDC,omitempty"`
	LogIt            bool     `json:"logIt,omitempty"`
	CheckForLength   bool     `json:"checkForLength,omitempty"`
	URLFriendly      bool     `json:"urlFriendly,omitempty"`
	AllowedLanguages []string `json:"allowedLanguages,omitempty"`
	AllowedCountries []string `json:"allowedCountries,omitempty"`
	BlockedCountries []string `json:"blockedCountries,omitempty"`
}

// SpamDetectionResponse represents the response from the spam detection endpoint
type SpamDetectionResponse struct {
	Score   int `json:"Score"`
	Details struct {
		IsIPBlocked       bool     `json:"isIPBlocked"`
		IsEmailBlocked    bool     `json:"isEmailBlocked"`
		IsContentSpam     string   `json:"isContentSpam"`
		LangMatch         bool     `json:"langMatch"`
		CountryMatch      bool     `json:"countryMatch"`
		NumberOfSpamWords int      `json:"numberOfSpamWords"`
		SpamWords         []string `json:"spamWords"`
		IsContentTooShort bool     `json:"isContentTooShort"`
	} `json:"Details"`
}

// DomainReputationRequest represents the request body for domain reputation check
type DomainReputationRequest struct {
	Domain string `json:"domain"`
}

// DomainReputationResponse represents the response from the domain reputation endpoint
type DomainReputationResponse struct {
	Blocked bool     `json:"Blocked"`
	Blocker []string `json:"Blocker"`
}

// makeRequest is a helper function to make HTTP requests to the OOPSpam API
func (c *Client) makeRequest(endpoint string, requestBody any, responseBody any) error {
	url := fmt.Sprintf("%s/%s", c.baseURL, endpoint)

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("error marshaling request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error: status code %d, body: %s", resp.StatusCode, string(body))
	}

	if responseBody != nil {
		err = json.NewDecoder(resp.Body).Decode(responseBody)
		if err != nil {
			return fmt.Errorf("error decoding response: %w", err)
		}
	}

	return nil
}

// CheckSpam checks if the given content is spam
func (c *Client) CheckSpam(req *SpamDetectionRequest) (*SpamDetectionResponse, error) {
	var result SpamDetectionResponse
	err := c.makeRequest("spamdetection", req, &result)
	return &result, err
}

// CheckDomainReputation checks the reputation of a domain
func (c *Client) CheckDomainReputation(domain string) (*DomainReputationResponse, error) {
	var result DomainReputationResponse

	err := c.makeRequest("reputation/domain",
		DomainReputationRequest{Domain: domain},
		&result,
	)

	return &result, err
}

// ReportSpam reports a false positive or false negative to OOPSpam
func (c *Client) ReportSpam(req *SpamDetectionRequest, shouldBeSpam bool) error {
	type reportRequest struct {
		*SpamDetectionRequest
		ShouldBeSpam bool `json:"shouldBeSpam"`
	}

	reportReq := reportRequest{
		SpamDetectionRequest: req,
		ShouldBeSpam:         shouldBeSpam,
	}

	return c.makeRequest("spamdetection/report", reportReq, nil)
}
