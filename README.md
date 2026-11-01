# smd-HeaderAnalyzer
Analyzes HTTP response headers for common security misconfigurations like missing security headers (e.g., Strict-Transport-Security, X-Frame-Options) and reports potential vulnerabilities.  It fetches a given URL, analyzes the headers, and provides a concise summary of security header status. - Focused on Identifies common security misconfigurations in cloud environments and deployed applications. Includes checks for exposed ports, default credentials, insecure API endpoints, and public cloud storage misconfigurations. Aims to provide actionable recommendations for remediation based on detected vulnerabilities. Leans towards identifying publicly facing misconfigurations.

## Install
`git clone https://github.com/ShadowStrikeHQ/smd-headeranalyzer`

## Usage
`./smd-headeranalyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: Enable verbose output for debugging.

## Authorized use

Use this tool only on targets you are authorized to test. Headers are analyzed for any completed HTTP response, including 404 and 500 responses; exit status 1 is reserved for connection and protocol failures. In the detailed header dump, Set-Cookie values are masked and never printed in clear.

## License
Copyright (c) ShadowStrikeHQ
