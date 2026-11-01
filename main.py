#!/usr/bin/env python3

import argparse
import logging
import re
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
        # requests follows redirects, and only the final response headers
        # are judged. A redirector that sends no security headers and lands
        # on a hardened page reports as hardened, and the reverse as well.
        response = requests.get(url, timeout=10) # Added timeout for requests
        # Any completed HTTP response is analyzed, including 404 and 500.
        # Exit 1 in main is reserved for connection and protocol failures,
        # which arrive here as RequestException and return None.
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

def is_valid_header_value(header, value):
    """
    Checks a header value against the valid forms for that header.
    The stored recommendation text is guidance only and is never used
    as the comparison target.
    """
    text = str(value).strip()
    if header == "X-Frame-Options":
        upper = text.upper()
        # ALLOW-FROM counts as valid here even though current browsers
        # ignore it. A page relying on it reports as correctly configured
        # while modern framing protection is absent.
        return upper in ("DENY", "SAMEORIGIN") or upper.startswith("ALLOW-FROM ")
    if header == "Strict-Transport-Security":
        match = re.search(r'max-age\s*=\s*(\d+)', text, re.IGNORECASE)
        # Any positive max-age passes, including max-age=1. I check that the
        # directive is well formed, not that it is anywhere near the one year
        # figure the recommendation text quotes.
        return match is not None and int(match.group(1)) > 0
    if header == "Content-Security-Policy":
        return len(text) > 0
    if header == "X-Content-Type-Options":
        return text.lower() == "nosniff"
    if header == "Referrer-Policy":
        return text.lower() in (
            "no-referrer", "no-referrer-when-downgrade", "origin",
            "origin-when-cross-origin", "same-origin", "strict-origin",
            "strict-origin-when-cross-origin", "unsafe-url",
        )
    # Guidance-only headers (for example Permissions-Policy): a non empty
    # value is reported, not graded against placeholder text.
    return len(text) > 0


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
            if is_valid_header_value(header, headers[header]):
                print(f"    - Value: {headers[header]}")
            else:
                print(f"    - Value Mismatch: Guidance '{recommendation['value']}', found '{headers[header]}'")

        else:
            print(f"  {header}: Missing")
            print(f"    - Recommendation: {recommendation['description']}")
            print(f"    - Remediation: {recommendation['remediation']}")
    print("\nDetailed Headers:")
    for header, value in headers.items():
        # Set-Cookie is the only value masked in the detailed dump. Any other
        # header the server chose to send, including tokens in custom
        # headers, prints in clear below.
        if header.lower() == "set-cookie":
            print(f"  {header}: [MASKED]")
        else:
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

    # headers is a dict of the response headers, so this tests emptiness
    # as well as failure. A reachable server that answers with no headers
    # at all takes the failure exit, with a message blaming the URL.
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