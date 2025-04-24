#!/usr/bin/env python3

import argparse
import logging
import requests
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Security Header Recommendations
SECURITY_HEADER_RECOMMENDATIONS = {
    "Strict-Transport-Security": {
        "presence": "required",
        "value": "max-age=31536000; includeSubDomains; preload",
        "description": "Enforces HTTPS for secure connections.",
        "remediation": "Configure your web server to include the Strict-Transport-Security header in all HTTPS responses."
    },
    "X-Frame-Options": {
        "presence": "required",
        "value": "DENY or SAMEORIGIN",
        "description": "Protects against clickjacking attacks.",
        "remediation": "Set X-Frame-Options to DENY or SAMEORIGIN in your web server configuration."
    },
    "X-Content-Type-Options": {
        "presence": "required",
        "value": "nosniff",
        "description": "Prevents MIME-sniffing vulnerabilities.",
        "remediation": "Configure your web server to send the X-Content-Type-Options: nosniff header."
    },
    "Content-Security-Policy": {
        "presence": "recommended",
        "value": "Define a strict policy tailored to your application's needs",
        "description": "Controls resources the user agent is allowed to load.",
        "remediation": "Implement a Content Security Policy (CSP) that allows only trusted sources for scripts, stylesheets, images, and other resources."
    },
    "Referrer-Policy": {
        "presence": "recommended",
        "value": "strict-origin-when-cross-origin",
        "description": "Controls how much referrer information is sent with requests.",
        "remediation": "Set the Referrer-Policy header to a suitable value like strict-origin-when-cross-origin."
    },
    "Permissions-Policy": {
        "presence": "recommended",
        "value": "Define a policy tailored to your application's needs",
        "description": "Controls browser features that the site can use.",
        "remediation": "Implement a Permissions-Policy header to control access to browser features."
    }
}


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Analyzes HTTP response headers for security misconfigurations.")
    parser.add_argument("url", help="The URL to analyze.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for debugging.")
    return parser.parse_args()


def analyze_headers(url):
    """
    Fetches the headers from a given URL and analyzes them for security misconfigurations.

    Args:
        url (str): The URL to analyze.

    Returns:
        dict: A dictionary containing the analysis results.
    """
    try:
        response = requests.get(url, timeout=10) # Added timeout for requests
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        headers = response.headers
        return headers
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching URL: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def validate_url(url):
    """
    Validates the URL to ensure it is a valid HTTP or HTTPS URL.
    Args:
        url (str): The URL to validate.
    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    if not url.startswith("http://") and not url.startswith("https://"):
        logging.error("Invalid URL format.  Must start with http:// or https://")
        return False
    return True

def report_header_status(headers):
    """
    Reports the status of security headers based on the provided headers and recommendations.

    Args:
        headers (dict): A dictionary of HTTP headers.
    """
    if headers is None:
        print("Failed to retrieve headers.  Check the URL and your network connection.")
        return

    print("Security Header Analysis:")
    for header, recommendation in SECURITY_HEADER_RECOMMENDATIONS.items():
        if header in headers:
            print(f"  {header}: Present")
            if recommendation["value"] != "Define a policy tailored to your application's needs":
                if headers[header] != recommendation["value"]:
                    print(f"    - Value Mismatch: Expected '{recommendation['value']}', found '{headers[header]}'")
            else:
                 print(f"    - Value: {headers[header]}")

        else:
            print(f"  {header}: Missing")
            print(f"    - Recommendation: {recommendation['description']}")
            print(f"    - Remediation: {recommendation['remediation']}")
    print("\nDetailed Headers:")
    for header, value in headers.items():
        print(f"  {header}: {value}")


def main():
    """
    Main function to execute the header analysis.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    url = args.url

    if not validate_url(url):
        sys.exit(1)

    logging.info(f"Analyzing URL: {url}")

    headers = analyze_headers(url)

    if headers:
        report_header_status(headers)
    else:
        logging.error("Failed to analyze headers.  Check URL or network.")
        sys.exit(1)

if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Analyze a URL: ./smd-HeaderAnalyzer.py https://example.com
# 2. Analyze a URL with verbose output: ./smd-HeaderAnalyzer.py -v https://example.com