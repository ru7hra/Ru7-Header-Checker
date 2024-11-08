#!/usr/bin/env python3
"""
Ru7 Header Checker Script

This script performs comprehensive security header checks on given URLs.
It checks for the presence and correctness of essential security headers,
validates their values using multiple methods, handles input in various formats,
and generates detailed reports.

Usage:
    python ru7_header_checker.py [options] [URLs]

Options:
    -h, --help          Show this help message and exit
    -u, --url           Single URL to check
    -l, --list          Comma-separated list of URLs
    -f, --file          Path to a text file containing URLs (one per line)
    -o, --output        Output directory for reports (default: current directory)
    -t, --threads       Number of threads for parallel processing (default: 10)
    -v, --verbose       Increase output verbosity (can be used multiple times)
    --save-headers      Save curated headers. Options: none (default), single, all
    --version           Show script version and exit
"""

import requests
import re
import csv
import json
import logging
import argparse
import sys
import os
import threading
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from time import sleep
from tqdm import tqdm
from collections import defaultdict

# Configure logging
logger = logging.getLogger('Ru7HeaderChecker')
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Constants
SCRIPT_VERSION = '1.2'  # Updated version
REQUIRED_HEADERS = [
    'Permissions-Policy',
    'X-Frame-Options',
    'Content-Security-Policy',
    'X-Content-Type-Options',
    'Referrer-Policy',
    'X-XSS-Protection',
    'Strict-Transport-Security',
    'Expect-CT',
    'Cache-Control',
    'X-Permitted-Cross-Domain-Policies',
    'X-DNS-Prefetch-Control',
    'X-Download-Options'
]

ADDITIONAL_HEADERS = [
    'Access-Control-Allow-Origin',
    'Access-Control-Allow-Credentials',
    'Public-Key-Pins',
    'Server',
    'Set-Cookie',
    'Cross-Origin-Resource-Policy',
    'Cross-Origin-Embedder-Policy',
    'Cross-Origin-Opener-Policy',
    'Content-Disposition',
    'Content-Type'
]

MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds
TIMEOUT = 10  # seconds
MAX_REDIRECTS = 3
DEFAULT_THREADS = 10  # Default number of threads

# Global Events for pause/resume and shutdown
pause_event = threading.Event()
shutdown_event = threading.Event()


def validate_url(url):
    """
    Validate the URL format and prepend 'http://' if missing.

    Parameters:
        url (str): The URL to validate.

    Returns:
        str or None: Validated URL or None if invalid.
    """
    if not re.match(r'^http(s)?://', url, re.IGNORECASE):
        url = 'http://' + url
    parsed = urlparse(url)
    if not parsed.netloc:
        return None
    return url


def fetch_url(url):
    """
    Fetch the URL with retries, redirects, and error handling.

    Parameters:
        url (str): The URL to fetch.

    Returns:
        list or None: A list of Response objects representing each step in the redirect chain,
                      or None if failed after retries.
    """
    attempt = 0
    while attempt < MAX_RETRIES and not shutdown_event.is_set():
        try:
            responses = []
            response = requests.get(url, allow_redirects=False, timeout=TIMEOUT)
            responses.append(response)
            redirect_count = 0
            while response.is_redirect and redirect_count < MAX_REDIRECTS:
                redirect_url = response.headers.get('Location')
                if not redirect_url:
                    break
                # Handle relative redirects
                redirect_url_parsed = urlparse(redirect_url)
                if not redirect_url_parsed.scheme:
                    redirect_url = urlparse(response.url).scheme + '://' + urlparse(response.url).netloc + redirect_url
                response = requests.get(redirect_url, allow_redirects=False, timeout=TIMEOUT)
                responses.append(response)
                redirect_count += 1
            return responses
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching {url}: {e}")
            attempt += 1
            sleep(RETRY_DELAY)
    return None


def check_headers(url, save_headers_option):
    """
    Check the security headers of the given URL and validate their values using multiple methods.

    Parameters:
        url (str): The URL to check.
        save_headers_option (str): 'none', 'single', or 'all' to determine header saving.

    Returns:
        dict: A dictionary containing the results of the header checks.
    """
    result = {
        'url': url,
        'headers_found': [],
        'headers_missing': [],
        'header_validation': defaultdict(list),
        'additional_headers_found': [],
        'duplicate_headers': [],
        'non_standard_headers': [],
        'https_default': False,
        'response_time': 0,
        'error': '',
        'saved_headers': {}  # NEW FEATURE
    }

    if shutdown_event.is_set():
        result['error'] = 'Shutdown initiated.'
        return result

    responses = fetch_url(url)
    if not responses:
        result['error'] = 'Failed to fetch URL after retries.'
        return result

    final_response = responses[-1]

    # Handle save_headers_option
    saved_headers = {}
    if save_headers_option == 'single':
        saved_headers['final'] = dict(final_response.headers)
    elif save_headers_option == 'all':
        for idx, response in enumerate(responses):
            key = f"response_{idx + 1}"
            saved_headers[key] = dict(response.headers)

    if save_headers_option != 'none':
        result['saved_headers'] = saved_headers

    # Check if the URL defaults to HTTPS
    if urlparse(final_response.url).scheme.lower() == 'https':
        result['https_default'] = True

    headers = final_response.headers
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Check for required headers
    for header in REQUIRED_HEADERS:
        if header.lower() in headers_lower:
            result['headers_found'].append(header)
        else:
            result['headers_missing'].append(header)

    # Validate header values using multiple methods
    result['header_validation'] = validate_header_values(headers, final_response.url)

    # Detect additional headers
    additional_headers_found = []
    for header in ADDITIONAL_HEADERS:
        if header.lower() in headers_lower:
            additional_headers_found.append(header)
    result['additional_headers_found'] = additional_headers_found

    # Detect duplicate headers
    result['duplicate_headers'] = detect_duplicate_headers(final_response)

    # Detect non-standard headers
    result['non_standard_headers'] = detect_non_standard_headers(headers)

    # Check for performance issues
    result['response_time'] = final_response.elapsed.total_seconds()

    return result


def detect_duplicate_headers(response):
    """
    Detect duplicate headers in the response.

    Parameters:
        response (Response): The HTTP response object.

    Returns:
        list: List of duplicate headers.
    """
    headers = response.raw.headers
    header_counts = defaultdict(int)
    for header in headers.items():
        header_counts[header[0].lower()] += 1
    duplicates = [header for header, count in header_counts.items() if count > 1]
    return duplicates


def detect_non_standard_headers(headers):
    """
    Identify non-standard headers in the response.

    Parameters:
        headers (dict): The response headers.

    Returns:
        list: List of non-standard headers.
    """
    standard_headers = [header.lower() for header in REQUIRED_HEADERS + ADDITIONAL_HEADERS]
    non_standard = [header for header in headers if header.lower() not in standard_headers]
    return non_standard


def validate_header_values(headers, url):
    """
    Validate specific header values as per requirements using multiple methods.

    Parameters:
        headers (dict): The headers from the HTTP response.
        url (str): The URL being checked.

    Returns:
        defaultdict(list): A dictionary with validation results for specific headers.
    """
    validation = defaultdict(list)

    # Strict-Transport-Security: Multiple methods
    hsts = headers.get('Strict-Transport-Security', '')
    # Method 1: Confirm presence of max-age parameter
    if 'max-age' in hsts.lower():
        max_age_value = re.search(r'max-age=(\d+)', hsts.lower())
        if max_age_value and int(max_age_value.group(1)) >= 31536000:
            validation['Strict-Transport-Security'].append('Method 1: Valid - max-age >= 1 year')
        else:
            validation['Strict-Transport-Security'].append('Method 1: Warning - max-age less than 1 year')
    else:
        validation['Strict-Transport-Security'].append('Method 1: Invalid - max-age missing')

    # Method 2: Check if includeSubDomains is set
    if 'includesubdomains' in hsts.lower():
        validation['Strict-Transport-Security'].append('Method 2: Valid - includeSubDomains set')
    else:
        validation['Strict-Transport-Security'].append('Method 2: Warning - includeSubDomains not set')

    # Method 3: Verify preload directive
    if 'preload' in hsts.lower():
        validation['Strict-Transport-Security'].append('Method 3: Valid - preload set')
    else:
        validation['Strict-Transport-Security'].append('Method 3: Info - preload not set')

    # Additional HSTS check: Ensure HSTS is set only on HTTPS
    if not urlparse(url).scheme == 'https':
        validation['Strict-Transport-Security'].append('Warning: HSTS should only be set on HTTPS responses')

    # Content-Security-Policy: Multiple methods
    csp = headers.get('Content-Security-Policy', '')
    # Method 1: Check for unsafe directives
    if 'unsafe-inline' in csp.lower() or 'unsafe-eval' in csp.lower():
        validation['Content-Security-Policy'].append('Method 1: Warning - Contains unsafe directives')
    else:
        validation['Content-Security-Policy'].append('Method 1: Valid')

    # Method 2: Check for default-src directive
    if 'default-src' in csp.lower():
        validation['Content-Security-Policy'].append('Method 2: Valid - default-src set')
    else:
        validation['Content-Security-Policy'].append('Method 2: Warning - default-src not set')

    # Method 3: Check for 'object-src' directive
    if 'object-src' in csp.lower():
        validation['Content-Security-Policy'].append('Method 3: Valid - object-src set')
    else:
        validation['Content-Security-Policy'].append('Method 3: Warning - object-src not set')

    # X-Frame-Options: Multiple methods
    x_frame = headers.get('X-Frame-Options', '').upper()
    # Method 1: Check for DENY or SAMEORIGIN
    if x_frame in ['DENY', 'SAMEORIGIN']:
        validation['X-Frame-Options'].append('Method 1: Valid value')
    else:
        validation['X-Frame-Options'].append('Method 1: Invalid or missing value')

    # Method 2: Check for ALLOW-FROM directive
    if 'ALLOW-FROM' in x_frame:
        validation['X-Frame-Options'].append('Method 2: ALLOW-FROM detected, may be deprecated')
    else:
        validation['X-Frame-Options'].append('Method 2: ALLOW-FROM not used')

    # Additional check: Validate ALLOW-FROM URL
    if 'ALLOW-FROM' in x_frame:
        parts = x_frame.split('ALLOW-FROM')
        if len(parts) > 1:
            allow_from_url = parts[1].strip()
            if validate_url(allow_from_url):
                validation['X-Frame-Options'].append('Method 3: Valid ALLOW-FROM URL')
            else:
                validation['X-Frame-Options'].append('Method 3: Invalid ALLOW-FROM URL')
        else:
            validation['X-Frame-Options'].append('Method 3: Invalid ALLOW-FROM syntax')

    # Referrer-Policy: Multiple methods
    referrer_policy = headers.get('Referrer-Policy', '').lower()
    # Method 1: Check for strict values
    secure_values = [
        'no-referrer', 'strict-origin', 'strict-origin-when-cross-origin'
    ]
    if referrer_policy in secure_values:
        validation['Referrer-Policy'].append('Method 1: Valid secure value')
    else:
        validation['Referrer-Policy'].append('Method 1: Less secure value')

    # Method 2: Check for missing header
    if not referrer_policy:
        validation['Referrer-Policy'].append('Method 2: Header missing')

    # X-Content-Type-Options: Multiple methods
    x_content_type_options = headers.get('X-Content-Type-Options', '')
    # Method 1: Check if set to 'nosniff' with exact case
    if x_content_type_options.lower() == 'nosniff':
        validation['X-Content-Type-Options'].append('Method 1: Valid')
    else:
        validation['X-Content-Type-Options'].append('Method 1: Invalid or missing value')

    # X-XSS-Protection: Multiple methods
    x_xss_protection = headers.get('X-XSS-Protection', '')
    # Method 1: Should be '1; mode=block'
    if x_xss_protection.lower() == '1; mode=block':
        validation['X-XSS-Protection'].append('Method 1: Valid')
    elif x_xss_protection.lower() == '0':
        validation['X-XSS-Protection'].append('Method 1: Warning - Protection disabled')
    else:
        validation['X-XSS-Protection'].append('Method 1: Invalid or missing value')

    # Additional check: Warn about deprecation
    validation['X-XSS-Protection'].append('Note: X-XSS-Protection is deprecated in modern browsers')

    # Permissions-Policy: Multiple methods
    permissions_policy = headers.get('Permissions-Policy', '')
    # Method 1: Validate syntax
    if permissions_policy:
        validation['Permissions-Policy'].append('Method 1: Header present')
        # Method 2: Check for deprecated features
        deprecated_features = ['geolocation', 'camera', 'microphone']
        if any(feature in permissions_policy.lower() for feature in deprecated_features):
            validation['Permissions-Policy'].append('Method 2: Warning - Deprecated features used')
    else:
        validation['Permissions-Policy'].append('Method 1: Header missing')

    # Expect-CT: Multiple methods
    expect_ct = headers.get('Expect-CT', '')
    # Method 1: Check for max-age parameter
    if 'max-age' in expect_ct.lower():
        validation['Expect-CT'].append('Method 1: Valid - max-age present')
    else:
        validation['Expect-CT'].append('Method 1: Invalid - max-age missing')

    # Method 2: Check for enforce directive
    if 'enforce' in expect_ct.lower():
        validation['Expect-CT'].append('Method 2: Valid - enforce present')
    else:
        validation['Expect-CT'].append('Method 2: Info - enforce not set')

    # Method 3: Validate report-uri
    if 'report-uri' in expect_ct.lower():
        validation['Expect-CT'].append('Method 3: Valid - report-uri set')
    else:
        validation['Expect-CT'].append('Method 3: Warning - report-uri not set')

    # Cache-Control: Multiple methods
    cache_control = headers.get('Cache-Control', '').lower()
    # Method 1: Check for 'no-store' directive
    if 'no-store' in cache_control:
        validation['Cache-Control'].append('Method 1: Valid - no-store set')
    else:
        validation['Cache-Control'].append('Method 1: Info - no-store not set')

    # Method 2: Check for 'private' directive
    if 'private' in cache_control:
        validation['Cache-Control'].append('Method 2: Valid - private set')
    else:
        validation['Cache-Control'].append('Method 2: Info - private not set')

    # Access-Control-Allow-Origin: Multiple methods
    acao = headers.get('Access-Control-Allow-Origin', '')
    # Method 1: Check header presence
    if 'Access-Control-Allow-Origin' in headers:
        validation['Access-Control-Allow-Origin'].append('Method 1: Header present')
    else:
        validation['Access-Control-Allow-Origin'].append('Method 1: Header missing')

    # Method 2: Validate value is not '*'
    if acao == '*':
        validation['Access-Control-Allow-Origin'].append('Method 2: Warning - wildcard (*) used')
    elif acao:
        validation['Access-Control-Allow-Origin'].append('Method 2: Valid value')
    else:
        validation['Access-Control-Allow-Origin'].append('Method 2: Header missing')

    # Set-Cookie: Multiple methods
    cookies = headers.get('Set-Cookie', '')
    if cookies:
        cookie_validation = validate_cookies(cookies, final_response.url)
        validation['Set-Cookie'].extend(cookie_validation)
    else:
        validation['Set-Cookie'].append('No cookies set')

    # Server: Check for version disclosure
    server_header = headers.get('Server', '')
    if server_header:
        if re.search(r'/\d', server_header):
            validation['Server'].append('Warning: Server version disclosed')
        else:
            validation['Server'].append('Info: Server version not disclosed')
    else:
        validation['Server'].append('Info: Server header not present')

    # Content-Type: Check for dangerous MIME types
    content_type = headers.get('Content-Type', '')
    if content_type:
        if 'text/html' in content_type.lower() or 'application/json' in content_type.lower():
            validation['Content-Type'].append('Info: Content-Type seems appropriate')
        else:
            validation['Content-Type'].append('Warning: Unexpected Content-Type')
    else:
        validation['Content-Type'].append('Warning: Content-Type header missing')

    # Content-Disposition: Prevent MIME sniffing
    content_disposition = headers.get('Content-Disposition', '')
    if content_disposition:
        validation['Content-Disposition'].append('Info: Content-Disposition header present')
    else:
        validation['Content-Disposition'].append('Warning: Content-Disposition header missing')

    # Cross-Origin-Resource-Policy
    corp = headers.get('Cross-Origin-Resource-Policy', '')
    if corp:
        if corp.lower() in ['same-origin', 'same-site', 'cross-origin']:
            validation['Cross-Origin-Resource-Policy'].append('Valid value')
        else:
            validation['Cross-Origin-Resource-Policy'].append('Invalid value')
    else:
        validation['Cross-Origin-Resource-Policy'].append('Header missing')

    # Cross-Origin-Embedder-Policy
    coep = headers.get('Cross-Origin-Embedder-Policy', '')
    if coep:
        if coep.lower() == 'require-corp':
            validation['Cross-Origin-Embedder-Policy'].append('Valid - require-corp set')
        else:
            validation['Cross-Origin-Embedder-Policy'].append('Invalid value')
    else:
        validation['Cross-Origin-Embedder-Policy'].append('Header missing')

    # Cross-Origin-Opener-Policy
    coop = headers.get('Cross-Origin-Opener-Policy', '')
    if coop:
        if coop.lower() in ['same-origin', 'same-origin-allow-popups']:
            validation['Cross-Origin-Opener-Policy'].append('Valid value')
        else:
            validation['Cross-Origin-Opener-Policy'].append('Invalid value')
    else:
        validation['Cross-Origin-Opener-Policy'].append('Header missing')

    # X-Permitted-Cross-Domain-Policies
    x_permitted_policies = headers.get('X-Permitted-Cross-Domain-Policies', '').lower()
    if x_permitted_policies in ['none', 'master-only', 'by-content-type']:
        validation['X-Permitted-Cross-Domain-Policies'].append('Method 1: Valid value')
    elif x_permitted_policies == 'all':
        validation['X-Permitted-Cross-Domain-Policies'].append('Method 1: Warning - Too permissive (all)')
    else:
        validation['X-Permitted-Cross-Domain-Policies'].append('Method 1: Invalid or missing value')

    # X-DNS-Prefetch-Control
    x_dns_prefetch = headers.get('X-DNS-Prefetch-Control', '').lower()
    if x_dns_prefetch in ['on', 'off']:
        validation['X-DNS-Prefetch-Control'].append('Method 1: Valid value')
    else:
        validation['X-DNS-Prefetch-Control'].append('Method 1: Invalid or missing value')

    # X-Download-Options
    x_download_options = headers.get('X-Download-Options', '').lower()
    if x_download_options == 'noopen':
        validation['X-Download-Options'].append('Method 1: Valid value')
    else:
        validation['X-Download-Options'].append('Method 1: Invalid or missing value')

    return validation


def validate_cookies(cookie_header, url):
    """
    Validate the security attributes of cookies using multiple methods.

    Parameters:
        cookie_header (str): The Set-Cookie header string.
        url (str): The URL being checked.

    Returns:
        list: Validation results of the cookies.
    """
    validations = []
    # Split cookies by comma followed by space, ensuring we don't split within quotes
    cookies = re.split(r', (?=[^;]+;)', cookie_header)
    insecure_cookies = []
    for cookie in cookies:
        cookie = cookie.strip()
        attributes = cookie.split(';')
        flags = [attr.strip().lower() for attr in attributes[1:]]
        cookie_name = attributes[0].split('=')[0]
        # Method 1: Check for Secure flag
        if 'secure' in flags:
            validations.append(f"Cookie '{cookie_name}' Method 1: Secure flag set")
        else:
            validations.append(f"Cookie '{cookie_name}' Method 1: Secure flag missing")
            insecure_cookies.append(cookie_name)

        # Method 2: Check for HttpOnly flag
        if 'httponly' in flags:
            validations.append(f"Cookie '{cookie_name}' Method 2: HttpOnly flag set")
        else:
            validations.append(f"Cookie '{cookie_name}' Method 2: HttpOnly flag missing")
            insecure_cookies.append(cookie_name)

        # Method 3: Check for SameSite attribute
        same_site = next((flag.split('=')[1].lower() for flag in flags if 'samesite' in flag), '')
        if same_site in ['lax', 'strict', 'none']:
            validations.append(f"Cookie '{cookie_name}' Method 3: SameSite attribute set to {same_site}")
            if same_site == 'none' and urlparse(url).scheme != 'https':
                validations.append(f"Cookie '{cookie_name}' Warning: SameSite=None on insecure origin")
        else:
            if any('samesite' in flag for flag in flags):
                validations.append(f"Cookie '{cookie_name}' Method 3: Invalid SameSite value")
            else:
                validations.append(f"Cookie '{cookie_name}' Method 3: SameSite attribute missing")
            insecure_cookies.append(cookie_name)

        # Method 4: Check for Path and Domain attributes
        if not any('path=' in flag for flag in flags):
            validations.append(f"Cookie '{cookie_name}' Method 4: Warning - Path attribute missing")
        if not any('domain=' in flag for flag in flags):
            validations.append(f"Cookie '{cookie_name}' Method 4: Warning - Domain attribute missing")

    if insecure_cookies:
        validations.append(f"Insecure cookies found: {', '.join(set(insecure_cookies))}")
    else:
        validations.append("All cookies have Secure, HttpOnly, and SameSite attributes")

    return validations


def select_file_via_dialog():
    """
    Open a file selection dialog and return the selected file path.

    Returns:
        str or None: Path to the selected file or None if canceled.
    """
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()  # Hide the root window
        root.attributes("-topmost", True)  # Bring the dialog to the front
        file_path = filedialog.askopenfilename(
            title="Select File Containing URLs",
            filetypes=(("Text Files", "*.txt"), ("All Files", "*.*"))
        )
        root.destroy()
        if file_path:
            return file_path
        else:
            return None
    except Exception as e:
        logger.error(f"Error opening file dialog: {e}")
        print(f"Error opening file dialog: {e}")
        return None


def listen_for_commands():
    """
    Listen for user input to pause, resume, or quit the script.
    """
    logger.info("\nCommands:\n  p - Pause\n  c - Continue\n  q - Quit")
    while not shutdown_event.is_set():
        try:
            key = input().lower()
            if key == 'p':
                if not pause_event.is_set():
                    pause_event.set()
                    logger.info("[Paused]")
            elif key == 'c':
                if pause_event.is_set():
                    pause_event.clear()
                    logger.info("[Resumed]")
            elif key == 'q':
                shutdown_event.set()
                logger.info("[Quitting...]")
        except EOFError:
            pass
        sleep(0.1)


def process_input(args):
    """
    Process input URLs from command-line arguments.

    Parameters:
        args: Parsed command-line arguments.

    Returns:
        list: A list of validated URLs.
    """
    urls = []
    if args.url:
        validated_url = validate_url(args.url)
        if validated_url:
            urls.append(validated_url)
        else:
            logger.error(f"Invalid URL format: {args.url}")
    elif args.list:
        for url in args.list.split(','):
            url = url.strip()
            validated_url = validate_url(url)
            if validated_url:
                urls.append(validated_url)
            else:
                logger.error(f"Invalid URL format: {url}")
    elif args.file is not None:
        if args.file == 'PROMPT' or args.file is True:
            # Prompt the user to select a file via dialog
            logger.info("No file specified with the -f option. Please select a file from the dialog.")
            selected_file = select_file_via_dialog()
            if selected_file:
                args.file = selected_file
            else:
                logger.error("No file selected. Exiting.")
                return urls
        # Now, args.file should be a string containing the filename
        if isinstance(args.file, str):
            try:
                with open(args.file, 'r', encoding='utf-8') as f:
                    for line in f:
                        url = line.strip()
                        if url:
                            validated_url = validate_url(url)
                            if validated_url:
                                urls.append(validated_url)
                            else:
                                logger.error(f"Invalid URL format: {url}")
            except FileNotFoundError:
                logger.error(f"File not found: {args.file}")
            except Exception as e:
                logger.error(f"Error reading file {args.file}: {e}")
        else:
            logger.error(f"Invalid file argument: {args.file}")
    else:
        logger.error("No URLs provided. Use -h for help.")
    return urls


def generate_reports(results, output_dir):
    """
    Generate detailed and summary reports in text, CSV, and JSON formats.

    Parameters:
        results (list): The list of results from header checks.
        output_dir (str): The directory to save the reports.
    """
    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Detailed report
    detailed_report = []
    summary_stats = {
        'total_urls': len(results),
        'secure_urls': 0,
        'missing_headers': {},
        'duplicate_headers': {},
        'non_standard_headers': {},
        'performance_issues': []
    }

    for result in results:
        if 'error' in result and result['error']:
            continue
        if (len(result['headers_missing']) == 0 and
            all(all('Valid' in v or 'Info' in v for v in validations)
                for validations in result['header_validation'].values())):
            summary_stats['secure_urls'] += 1
        for header in result['headers_missing']:
            summary_stats['missing_headers'][header] = summary_stats['missing_headers'].get(header, 0) + 1

        # Collect duplicate headers
        for header in result.get('duplicate_headers', []):
            summary_stats['duplicate_headers'][header] = summary_stats['duplicate_headers'].get(header, 0) + 1

        # Collect non-standard headers
        for header in result.get('non_standard_headers', []):
            summary_stats['non_standard_headers'][header] = summary_stats['non_standard_headers'].get(header, 0) + 1

        # Collect performance issues
        if result.get('response_time', 0) > 5:
            summary_stats['performance_issues'].append({
                'url': result['url'],
                'response_time': result['response_time']
            })

        detailed_report.append(result)

    # Summary report
    summary = {
        'total_urls': summary_stats['total_urls'],
        'secure_urls': summary_stats['secure_urls'],
        'secure_percentage': (summary_stats['secure_urls'] / summary_stats['total_urls']) * 100 if summary_stats['total_urls'] > 0 else 0,
        'missing_headers_count': summary_stats['missing_headers'],
        'duplicate_headers_count': summary_stats['duplicate_headers'],
        'non_standard_headers_count': summary_stats['non_standard_headers'],
        'performance_issues': summary_stats['performance_issues']
    }

    # Save reports
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    # JSON
    json_path = os.path.join(output_dir, f"ru7_report_{timestamp}.json")
    try:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump({'detailed_report': detailed_report, 'summary': summary}, f, indent=4)
    except Exception as e:
        logger.error(f"Failed to write JSON report: {e}")

    # CSV
    csv_path = os.path.join(output_dir, f"ru7_report_{timestamp}.csv")
    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                'URL', 'HTTPS Default', 'Error', 'Response Time', 'Duplicate Headers', 'Non-Standard Headers'
            ] + REQUIRED_HEADERS + ADDITIONAL_HEADERS + [f"{header} (Validation)" for header in REQUIRED_HEADERS + ADDITIONAL_HEADERS]
            # Include saved_headers in CSV
            if any(result.get('saved_headers') for result in results):
                fieldnames.append('Saved Headers')  # Optional field

            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for result in results:
                row = {
                    'URL': result.get('url', ''),
                    'HTTPS Default': result.get('https_default', False),
                    'Error': result.get('error', ''),
                    'Response Time': result.get('response_time', ''),
                    'Duplicate Headers': ', '.join(result.get('duplicate_headers', [])),
                    'Non-Standard Headers': ', '.join(result.get('non_standard_headers', []))
                }

                # Headers present/missing
                for header in REQUIRED_HEADERS + ADDITIONAL_HEADERS:
                    if header in result.get('headers_found', []):
                        row[header] = 'Present'
                    elif header in result.get('headers_missing', []):
                        row[header] = 'Missing'
                    else:
                        row[header] = 'Unknown'

                # Header validation results
                for header in REQUIRED_HEADERS + ADDITIONAL_HEADERS:
                    validations = result.get('header_validation', {}).get(header, [])
                    row[f"{header} (Validation)"] = ' | '.join(validations)

                # Saved Headers (NEW FEATURE)
                if result.get('saved_headers'):
                    # Convert the saved headers dict to a JSON string for CSV
                    row['Saved Headers'] = json.dumps(result['saved_headers'], indent=2)

                writer.writerow(row)
    except Exception as e:
        logger.error(f"Failed to write CSV report: {e}")

    # Text
    txt_path = os.path.join(output_dir, f"ru7_report_{timestamp}.txt")
    try:
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write("Detailed Report:\n")
            for result in results:
                f.write(f"URL: {result.get('url', '')}\n")
                f.write(f"HTTPS Default: {result.get('https_default', False)}\n")
                f.write(f"Response Time: {result.get('response_time', '')} seconds\n")
                f.write(f"Headers Found: {', '.join(result.get('headers_found', []))}\n")
                f.write(f"Headers Missing: {', '.join(result.get('headers_missing', []))}\n")
                f.write(f"Duplicate Headers: {', '.join(result.get('duplicate_headers', []))}\n")
                f.write(f"Non-Standard Headers: {', '.join(result.get('non_standard_headers', []))}\n")
                f.write("Header Validation:\n")
                for k, validations in result.get('header_validation', {}).items():
                    f.write(f"  {k}:\n")
                    for v in validations:
                        f.write(f"    - {v}\n")
                f.write(f"Additional Headers Found: {', '.join(result.get('additional_headers_found', []))}\n")
                # Saved Headers (NEW FEATURE)
                if result.get('saved_headers'):
                    f.write("Saved Headers:\n")
                    for key, headers in result['saved_headers'].items():
                        f.write(f"  {key}:\n")
                        for h_key, h_val in headers.items():
                            f.write(f"    {h_key}: {h_val}\n")
                f.write(f"Error: {result.get('error', '')}\n")
                f.write("\n")

            f.write("Summary Report:\n")
            f.write(f"Total URLs Checked: {summary['total_urls']}\n")
            f.write(f"Secure URLs: {summary['secure_urls']}\n")
            f.write(f"Secure Percentage: {summary['secure_percentage']:.2f}%\n")
            f.write("Missing Headers Count:\n")
            for header, count in summary['missing_headers_count'].items():
                f.write(f"  {header}: {count}\n")
            f.write("Duplicate Headers Count:\n")
            for header, count in summary['duplicate_headers_count'].items():
                f.write(f"  {header}: {count}\n")
            f.write("Non-Standard Headers Count:\n")
            for header, count in summary['non_standard_headers_count'].items():
                f.write(f"  {header}: {count}\n")
            f.write("Performance Issues (Response Time > 5 seconds):\n")
            for issue in summary['performance_issues']:
                f.write(f"  URL: {issue['url']} - Response Time: {issue['response_time']} seconds\n")
    except Exception as e:
        logger.error(f"Failed to write Text report: {e}")

    logger.info(f"\nReports generated in '{output_dir}':")
    logger.info(f" - {json_path}")
    logger.info(f" - {csv_path}")
    logger.info(f" - {txt_path}")


def main():
    """
    Main function to parse arguments and initiate header checks.
    """
    parser = argparse.ArgumentParser(description='Ru7 Header Checker')
    parser.add_argument('-u', '--url', help='Single URL to check')
    parser.add_argument('-l', '--list', help='Comma-separated list of URLs')
    parser.add_argument('-f', '--file', nargs='?', const='PROMPT', help='File containing URLs (one per line)')
    parser.add_argument('-o', '--output', default='.', help='Output directory for reports')
    parser.add_argument('-t', '--threads', type=int, default=DEFAULT_THREADS, help='Number of threads for parallel processing (default: 10)')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase output verbosity (can be used multiple times)')
    parser.add_argument('--save-headers', choices=['none', 'single', 'all'], default='none',
                        help='Save curated headers. Options: none (default), single, all')  # NEW FEATURE
    parser.add_argument('--version', action='version', version=f'%(prog)s {SCRIPT_VERSION}')
    args = parser.parse_args()

    # Set logging level based on verbosity
    if args.verbose >= 2:
        logger.setLevel(logging.DEBUG)
    elif args.verbose == 1:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    urls = process_input(args)
    if not urls:
        return

    # Start the command listener thread
    command_thread = threading.Thread(target=listen_for_commands, daemon=True)
    command_thread.start()

    results = []
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            # Initialize tqdm progress bar
            with tqdm(total=len(urls), desc="Processing URLs", unit="url") as pbar:
                # Submit tasks to executor
                future_to_url = {executor.submit(check_headers, url, args.save_headers): url for url in urls}
                for future in as_completed(future_to_url):
                    if shutdown_event.is_set():
                        break
                    while pause_event.is_set():
                        sleep(0.5)
                    try:
                        result = future.result()
                        results.append(result)
                        # Display each test being done
                        if args.verbose >= 1:
                            logger.info(f"\nTesting URL: {result.get('url', '')}")
                            for header, validations in result.get('header_validation', {}).items():
                                logger.info(f"Header: {header}")
                                for validation in validations:
                                    logger.info(f"  - {validation}")
                    except Exception as e:
                        url = future_to_url[future]
                        logger.error(f"Exception occurred while processing {url}: {e}")
                    pbar.update(1)
                    if shutdown_event.is_set():
                        break
    except KeyboardInterrupt:
        shutdown_event.set()
        logger.warning("Process interrupted by user. Saving partial results...")
    finally:
        # Shutdown the command listener
        shutdown_event.set()
        command_thread.join()
        if results:
            generate_reports(results, args.output)
            logger.info("Security header checks completed. Reports generated.")
        else:
            logger.warning("No results to generate reports.")


if __name__ == '__main__':
    main()
