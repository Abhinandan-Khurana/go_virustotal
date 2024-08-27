package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
)

type VirusTotalResponse struct {
	Subdomains []string `json:"subdomains"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: go run vt-subdomains.go domain.com")
		os.Exit(1)
	}

	domain := os.Args[1]
	apiKey := os.Getenv("VTAPIKEY")

	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "VTAPIKEY environment variable not set. Quitting.")
		os.Exit(1)
	}

	url := "https://www.virustotal.com/vtapi/v2/domain/report"
	params := fmt.Sprintf("?apikey=%s&domain=%s", apiKey, domain)
	resp, err := http.Get(url + params)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not connect to www.virustotal.com")
		os.Exit(1)
	}
	defer resp.Body.Close()

	var vtResponse VirusTotalResponse
	if err := json.NewDecoder(resp.Body).Decode(&vtResponse); err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding response: %v\n", err)
		os.Exit(1)
	}

	if len(vtResponse.Subdomains) == 0 {
		fmt.Printf("No domains found for %s\n", domain)
		os.Exit(0)
	}

	sort.Strings(vtResponse.Subdomains)
	for _, subdomain := range vtResponse.Subdomains {
		fmt.Println(subdomain)
	}
}
