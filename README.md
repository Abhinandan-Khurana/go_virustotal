This is a simple golang script to collect subdomains using the Virus Total API.

First setup an environment variable `VTAPIKEY` with your [Virus Total](https://www.virustotal.com) API key.

```shell
unset HISTFILE #to avoid logging your key to ~/.bash_history
export VTAPIKEY=<apikey>
```

## Usage

Example: `go run main.go example.com`

## Installation

```bash
go install -v github.com/abhinandan-khurana/go_virustotal@latest
```
