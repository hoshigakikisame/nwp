# No Wildcard Please
Eliminating common domain wildcard instances, by matching similar DNS answer from the corresponding parent.

> Disclaimer: This is an experimental tool, just to see if I can prove my hypothesis to differentiate common domain wildcard instances and the actual unique one using DNS proto to avoid using banner grabbing and http probing.

## What NWP for?
- It is designed to help security researchers and domain analysts identify and differentiate between soulless filler wildcard DNS records and unique soulful DNS records for domains. This can be particularly useful in penetration testing, bug bounty hunting, and domain enumeration tasks.
- The use case is to avoid the common pitfalls of wildcard DNS records, which can lead to false positives in security assessments and domain analysis (e.g., when a wildcard record is used to catch all subdomains, making it difficult to identify unique subdomains or services).
- I personally use it as a middleman between DNS resolver & bruteforcer tools e.g [puredns](https://github.com/d3mondev/puredns), [dnsx](https://github.com/projectdiscovery/dnsx); and http probing tools e.g [httpx](https://github.com/projectdiscovery/httpx), [httprobe](https://github.com/tomnomnom/httprobe), to filter out wildcard DNS records before they reach the probing stage.

## Installation
```bash
go install -v github.com/hoshigakikisame/nwp/cmd/nwp@latest
```

## Usage
```bash
$ nwp -h

  ___ _    _____
 / _ \ |/|/ / _ \
/_//_/__,__/ .__/
          /_/     v0.0.2

by @ferdirianrk


Usage:
  nwp [flags]

Flags:
   -c, -concurrency int                  Max concurrency (default 3)
   -w, -wildcards string                 Wildcards file path
   -s, -subdomains string                Subdomains file path
   -cfl, -common-fingerprints-limit int  Limit for common fingerprints to be generated (default 7)
   -o, -output string                    Output file path to save results
   -inwm, -include-non-wildcard-members  Include non-wildcard members in the output
   -v, -verbose                          Enable verbose output
   -q, -quiet                            Enable quiet mode (no logging)
```


Anyway, thanks to [infosec-au](https://github.com/infosec-au) for the inspiring name.