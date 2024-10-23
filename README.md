```
                         _                 __        __        __
   ____ _____     _   __(_)______  _______/ /_____  / /_____ _/ /
  / __ `/ __ \   | | / / / ___/ / / / ___/ __/ __ \/ __/ __ `/ /
 / /_/ / /_/ /   | |/ / / /  / /_/ (__  ) /_/ /_/ / /_/ /_/ / /
 \__, /\____/____|___/_/_/   \__,_/____/\__/\____/\__/\__,_/_/
/____/     /_____/
```

A simple Go tool to fetch subdomains of a domain using the VirusTotal API.

## Features

- Fetch subdomains for a single domain or a list from a file
- Supports output in TXT, CSV, or JSON formats
- Silent mode for minimal output
- Includes a banner and help menu

## Direct Installation

```bash
go install -v github.com/Abhinandan-Khurana/go_virustotal@latest
```

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/Abhinandan-Khurana/go_virustotal.git
   cd go_virustotal

   ```

2. **Build the tool:**

   ```bash
   go build -o dist/go_virustotal main.go
   ```

## Usage

### Set Your VirusTotal API Key

Export your VirusTotal API key as an environment variable:

```bash
export VT_API_KEY=YOUR_API_KEY
```

### Command-Line Options

- `-domain`: Target domain to fetch subdomains for
- `-list`: File containing a list of domains
- `-silent`: Silent mode; only outputs results
- `-txt`: Output results in TXT format
- `-csv`: Output results in CSV format
- `-json`: Output results in JSON format

### Examples

- **Single Domain:**

  ```bash
  go_virustotal -domain example.com
  ```

- **List of Domains:**

  ```bash
  go_virustotal -list domains.txt
  ```

- **Silent Mode:**

  ```bash
  go_virustotal -domain example.com -silent
  ```

- **Output in TXT Format:**

  ```bash
  go_virustotal -domain example.com -txt
  ```

- **Output in CSV Format:**

  ```bash
  go_virustotal -domain example.com -csv
  ```

- **Output in JSON Format:**

  ```bash
  go_virustotal -domain example.com -json
  ```

### Help Menu

For a list of all options:

```bash
go_virustotal -h
```

## Output Format

### JSON Example

```json
{
  "tool_name": "virustotal",
  "result": [
    {
      "domain_name": "example.com",
      "results": ["sub1.example.com", "sub2.example.com"]
    }
  ]
}
```

## Notes

- Only one output format (`-txt`, `-csv`, or `-json`) can be specified at a time.
- In silent mode, banners and informational messages are suppressed.
- Default behavior prints subdomains line by line if no output format is specified.

## License

This project is licensed under the MIT License.

---

_Created with <3 by [Abhinandan Khurana](https://github.com/Abhinandan-Khurana)_
