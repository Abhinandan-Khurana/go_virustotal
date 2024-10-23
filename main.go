package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

type ResultEntry struct {
	DomainName string   `json:"domain_name"`
	Results    []string `json:"results"`
}

type Output struct {
	ToolName string        `json:"tool_name"`
	Result   []ResultEntry `json:"result"`
}

type VirusTotalResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
	Meta struct {
		Count int `json:"count"`
	} `json:"meta"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

var (
	domain  = flag.String("domain", "", "Target domain")
	list    = flag.String("list", "", "File containing list of domains")
	silent  = flag.Bool("silent", false, "Silent mode: only output results")
	txt     = flag.Bool("txt", false, "Output results in TXT format")
	csv     = flag.Bool("csv", false, "Output results in CSV format")
	jsonOut = flag.Bool("json", false, "Output results in JSON format")
)

func init() {
	flag.Usage = func() {
		fmt.Println("Usage: go_virustotal [options]")
		fmt.Println("Options:")
		flag.PrintDefaults()
	}
}

func main() {
	flag.Parse()

	if !*silent {
		printBanner()
	}

	// Get API key from environment variable
	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		fmt.Println("Error: VT_API_KEY environment variable not set.")
		os.Exit(1)
	}

	var domains []string

	// Get the list of domains to process
	if *domain != "" {
		domains = append(domains, *domain)
	} else if *list != "" {
		file, err := os.Open(*list)
		if err != nil {
			fmt.Printf("Error opening file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			domains = append(domains, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading file: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Error: No domain provided. Use -domain or -list flag.")
		flag.Usage()
		os.Exit(1)
	}

	// Ensure only one output format is specified
	formatFlags := 0
	if *txt {
		formatFlags++
	}
	if *csv {
		formatFlags++
	}
	if *jsonOut {
		formatFlags++
	}
	if formatFlags > 1 {
		fmt.Println("Error: Only one of -txt, -csv, or -json can be specified.")
		os.Exit(1)
	}

	// Now process each domain
	results := make([]ResultEntry, 0)
	for _, d := range domains {
		subdomains, err := getSubdomains(d, apiKey)
		if err != nil {
			if !*silent {
				fmt.Printf("Error fetching subdomains for %s: %v\n", d, err)
			}
			continue
		}
		if *txt || *csv || *jsonOut {
			// Collect results for output
			results = append(results, ResultEntry{
				DomainName: d,
				Results:    subdomains,
			})
		} else {
			// Default behavior: print subdomains
			for _, subdomain := range subdomains {
				if *silent {
					fmt.Println(subdomain)
				} else {
					fmt.Printf("[%s] %s\n", d, subdomain)
				}
			}
		}
	}

	// Output results in requested format
	if *txt {
		// Output in TXT format
		for _, entry := range results {
			for _, subdomain := range entry.Results {
				fmt.Println(subdomain)
			}
		}
	} else if *csv {
		// Output in CSV format
		for _, entry := range results {
			for _, subdomain := range entry.Results {
				fmt.Printf("%s,%s\n", entry.DomainName, subdomain)
			}
		}
	} else if *jsonOut {
		// Output in JSON format
		output := Output{
			ToolName: "virustotal",
			Result:   results,
		}
		jsonBytes, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			fmt.Printf("Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(jsonBytes))
	}
}

func getSubdomains(domain, apiKey string) ([]string, error) {
	subdomains := make([]string, 0)
	baseURL := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains", domain)

	client := &http.Client{}
	url := baseURL

	for {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("x-apikey", apiKey)

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
		}

		var vtResp VirusTotalResponse
		err = json.Unmarshal(bodyBytes, &vtResp)
		if err != nil {
			return nil, err
		}

		for _, data := range vtResp.Data {
			subdomains = append(subdomains, data.ID)
		}

		if vtResp.Links.Next == "" {
			break
		} else {
			url = vtResp.Links.Next
		}
	}

	return subdomains, nil
}

func printBanner() {
	fmt.Println(
		`
                         _                 __        __        __
   ____ _____     _   __(_)______  _______/ /_____  / /_____ _/ /
  / __ \/ __ \   | | / / / ___/ / / / ___/ __/ __ \/ __/ __ \/ / 
 / /_/ / /_/ /   | |/ / / /  / /_/ (__  ) /_/ /_/ / /_/ /_/ / /  
 \__. /\____/____|___/_/_/   \__._/____/\__/\____/\__/\__._/_/   
/____/     /_____/                                                
                                            ~ L0u51f3r007    
  `)
}
