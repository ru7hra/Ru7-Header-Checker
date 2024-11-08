# Ru7-Header-Checker
Ru7 Header Checker is a robust and comprehensive Python tool designed to perform in-depth security header analysis on web URLs. Tailored for bug bounty hunters and penetration testers, this script ensures that web applications adhere to security best practices by meticulously checking and validating essential HTTP security headers.



**Features**
Evaluate the presence and correctness of essential security headers, including:

Content-Security-Policy
Strict-Transport-Security
X-Frame-Options
Referrer-Policy
X-Content-Type-Options
X-XSS-Protection
...and many others.

**Multiple Input Methods:**
Seamlessly check URLs provided via command-line arguments, comma-separated lists, or input files.

**Parallel Processing:**
Leverage multithreading to efficiently process multiple URLs concurrently, reducing scan time.

**Detailed Reporting:**
Generate comprehensive reports in JSON, CSV, and TXT formats, encapsulating detailed findings and summary statistics.

**Interactive Control:**
Dynamically pause, resume, or terminate scanning operations in real-time based on user input.

**Header Saving Options:**
Optionally save curated headers (none, single, all) for further analysis or auditing purposes.

**Error Handling & Retries:**
Robust mechanisms to handle network issues, redirects, and other potential errors with retry logic.

**Installation**
Ensure you have Python 3.6 or higher installed on your system. Follow the steps below to set up the Ru7 Header Checker:


**FAQs**

Q1: What is the purpose of the --save-headers option?
A1: The --save-headers option allows you to save the HTTP headers retrieved during the scan. You can choose to save no headers (none), only the final response headers (single), or all headers from each step in the redirect chain (all). This feature is useful for in-depth analysis or auditing purposes.

Q2: How does the script handle redirects?
A2: The script follows redirects manually up to a maximum of 3 times (MAX_REDIRECTS). It stores each response in the redirect chain, allowing you to save all headers if desired.

Q3: Can I scan a large number of URLs efficiently?
A3: Yes! By utilizing multithreading (-t or --threads option), you can scan multiple URLs concurrently, significantly reducing the total scanning time.

Q4: What happens if a URL fails to respond?
A4: The script implements retry logic (MAX_RETRIES and RETRY_DELAY) to handle transient network issues. If a URL fails to respond after the maximum retries, it logs the error and continues with the remaining URLs.

Q5: Are there any plans to integrate third-party APIs?
A5: Currently, the script is designed to operate without relying on third-party APIs to ensure privacy and reduce dependencies. However, future enhancements can consider optional integrations upon user request.

